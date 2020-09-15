package internal

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"code.cfops.it/sys/tubular/internal/lock"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc "$CLANG" -makebase "$MAKEDIR" dispatcher ../ebpf/inet-kern.c -- -mcpu=v2 -O2 -g -nostdinc -Wall -Werror -I../ebpf/include

// Errors returned by the Dispatcher.
var (
	ErrLoaded    = errors.New("dispatcher already loaded")
	ErrNotLoaded = errors.New("dispatcher not loaded")
)

// Dispatcher manipulates the socket dispatch data plane.
type Dispatcher struct {
	netns        *netns
	link         *link.RawLink
	Path         string
	bindings     *ebpf.Map
	destinations *destinations
	dir          *os.File
}

// CreateDispatcher loads the dispatcher into a network namespace.
//
// Returns ErrLoaded if the namespace already has the dispatcher enabled.
func CreateDispatcher(netnsPath, bpfFsPath string) (_ *Dispatcher, err error) {
	onError := func(fn func()) {
		if err != nil {
			fn()
		}
	}
	closeOnError := func(c io.Closer) {
		if err != nil {
			c.Close()
		}
	}

	specs, err := newDispatcherSpecs()
	if err != nil {
		return nil, err
	}

	netns, err := newNetns(netnsPath, bpfFsPath)
	if err != nil {
		return nil, err
	}
	defer closeOnError(netns)

	var (
		coll    *ebpf.Collection
		spec    = specs.CollectionSpec()
		pinPath = netns.DispatcherStatePath()
	)

	if err := os.Mkdir(pinPath, 0700); os.IsExist(err) {
		return nil, fmt.Errorf("create state directory %s: %w", pinPath, ErrLoaded)
	} else if err != nil {
		return nil, fmt.Errorf("create state directory: %s", err)
	}
	defer onError(func() {
		os.RemoveAll(pinPath)
	})

	dir, err := os.Open(pinPath)
	if err != nil {
		return nil, fmt.Errorf("can't open state directory: %s", err)
	}
	defer closeOnError(dir)

	if err := lock.TryLockExclusive(dir); err != nil {
		return nil, err
	}

	coll, err = ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("can't load BPF: %s", err)
	}
	defer coll.Close()

	for name, m := range coll.Maps {
		if err := m.Pin(filepath.Join(pinPath, name)); err != nil {
			return nil, fmt.Errorf("can't pin map %s: %s", name, err)
		}
	}

	var bpf dispatcherObjects
	if err := coll.Assign(&bpf); err != nil {
		return nil, fmt.Errorf("can't assign objects: %s", err)
	}
	defer closeOnError(&bpf)

	dests, err := createDestinations(&bpf, filepath.Join(pinPath, "destinations"))
	if err != nil {
		return nil, err
	}
	defer closeOnError(dests)

	attach, err := netns.AttachProgram(bpf.ProgramDispatcher)
	if err != nil {
		return nil, err
	}
	defer closeOnError(attach)

	linkPath := filepath.Join(pinPath, "link")
	if err := attach.Pin(linkPath); err != nil {
		return nil, fmt.Errorf("can't pin link: %s", err)
	}

	return &Dispatcher{netns, attach, pinPath, bpf.MapBindings, dests, dir}, nil
}

// OpenDispatcher loads an existing dispatcher from a namespace.
//
// Returns ErrNotLoaded if the dispatcher is not loaded yet.
func OpenDispatcher(netnsPath, bpfFsPath string) (_ *Dispatcher, err error) {
	closeOnError := func(c io.Closer) {
		if err != nil {
			c.Close()
		}
	}

	specs, err := newDispatcherSpecs()
	if err != nil {
		return nil, err
	}

	netns, err := newNetns(netnsPath, bpfFsPath)
	if err != nil {
		return nil, err
	}
	defer closeOnError(netns)

	var (
		coll    *ebpf.Collection
		spec    = specs.CollectionSpec()
		pinPath = netns.DispatcherStatePath()
	)

	dir, err := os.Open(pinPath)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("%s: %w", netnsPath, ErrNotLoaded)
	} else if err != nil {
		return nil, fmt.Errorf("%s: %s", netnsPath, err)
	}
	defer closeOnError(dir)

	if err := lock.TryLockExclusive(dir); err != nil {
		return nil, err
	}

	pinnedMaps := make(map[string]*ebpf.Map)
	for name, mapSpec := range spec.Maps {
		m, err := ebpf.LoadPinnedMap(filepath.Join(pinPath, name))
		if err != nil {
			return nil, fmt.Errorf("can't load pinned map %s: %s", name, err)
		}
		defer closeOnError(m)

		if err := checkMap(mapSpec, m); err != nil {
			return nil, fmt.Errorf("pinned map %s is incompatible: %s", name, err)
		}

		pinnedMaps[name] = m
	}

	if err := spec.RewriteMaps(pinnedMaps); err != nil {
		return nil, fmt.Errorf("can't use pinned maps: %s", err)
	}

	coll, err = ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("can't load BPF: %s", err)
	}

	// RewriteMaps removes maps from spec, so we have to
	// add them back here.
	coll.Maps = pinnedMaps

	var bpf dispatcherObjects
	if err := coll.Assign(&bpf); err != nil {
		return nil, fmt.Errorf("can't assign objects: %s", err)
	}
	defer closeOnError(&bpf)

	dests, err := openDestinations(&bpf, filepath.Join(pinPath, "destinations"))
	if err != nil {
		return nil, err
	}
	defer closeOnError(dests)

	linkPath := filepath.Join(pinPath, "link")
	attach, err := link.LoadPinnedRawLink(linkPath)
	if err != nil {
		return nil, fmt.Errorf("load dispatcher: %s", err)
	}

	// TODO: We should verify that the attached program tag (aka truncated sha1)
	// matches bpf.ProgramDispatcher.
	return &Dispatcher{netns, attach, pinPath, bpf.MapBindings, dests, dir}, nil
}

// Close frees associated resources.
//
// It does not remove the dispatcher, see Unload for that.
func (d *Dispatcher) Close() error {
	if err := d.link.Close(); err != nil {
		return fmt.Errorf("can't close link: %s", err)
	}
	if err := d.bindings.Close(); err != nil {
		return fmt.Errorf("can't close BPF objects: %s", err)
	}
	if err := d.destinations.Close(); err != nil {
		return fmt.Errorf("can't close destination IDs: %x", err)
	}
	if err := d.netns.Close(); err != nil {
		return fmt.Errorf("can't close netns handle: %s", err)
	}
	// Close the directory as the last step, since it releases the lock.
	if err := d.dir.Close(); err != nil {
		return fmt.Errorf("can't close state directory handle: %s", err)
	}
	return nil
}

// Unload removes the dispatcher.
//
// It isn't necessary to call Close() afterwards.
func (d *Dispatcher) Unload() error {
	if err := os.RemoveAll(d.Path); err != nil {
		return fmt.Errorf("can't remove pinned state: %s", err)
	}

	return d.Close()
}

type Domain uint8

const (
	AF_INET  Domain = unix.AF_INET
	AF_INET6 Domain = unix.AF_INET6
)

func (d Domain) String() string {
	switch d {
	case AF_INET:
		return "ipv4"
	case AF_INET6:
		return "ipv6"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(d))
	}
}

type Protocol uint8

// Valid protocols.
const (
	TCP Protocol = unix.IPPROTO_TCP
	UDP Protocol = unix.IPPROTO_UDP
)

func (p Protocol) String() string {
	switch p {
	case TCP:
		return "tcp"
	case UDP:
		return "udp"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(p))
	}
}

// AddBinding redirects traffic for a given protocol, prefix and port to a label.
//
// Traffic for the binding is dropped by the data plane if no matching
// destination exists.
//
// Returns an error if the binding is already pointing at the specified label.
func (d *Dispatcher) AddBinding(bind *Binding) (err error) {
	onError := func(fn func()) {
		if err != nil {
			fn()
		}
	}

	dest := newDestinationFromBinding(bind)

	id, err := d.destinations.AcquireID(dest)
	if err != nil {
		return fmt.Errorf("add binding: %s", err)
	}
	defer onError(func() { _ = d.destinations.ReleaseID(dest) })

	key, err := bind.key()
	if err != nil {
		return err
	}

	var existingID destinationID
	if err := d.bindings.Lookup(key, &existingID); err == nil {
		if existingID == id {
			// TODO: We could also turn this into a no-op?
			return fmt.Errorf("add binding: already bound to %s", bind)
		}
	}

	err = d.bindings.Update(key, id, 0)
	if err != nil {
		return fmt.Errorf("create binding: %s", err)
	}

	return nil
}

// RemoveBinding stops redirecting traffic for a given protocol, prefix and port.
//
// Returns an error if the binding doesn't exist.
func (d *Dispatcher) RemoveBinding(bind *Binding) error {
	key, err := bind.key()
	if err != nil {
		return err
	}

	var existingID destinationID
	if err := d.bindings.Lookup(key, &existingID); err != nil {
		return fmt.Errorf("remove binding: lookup destination: %s", err)
	}

	dest := newDestinationFromBinding(bind)
	if !d.destinations.HasID(dest, existingID) {
		return fmt.Errorf("remove binding: destination mismatch")
	}

	if err := d.bindings.Delete(key); err != nil {
		return fmt.Errorf("remove binding: %s", err)
	}

	// We err on the side of caution here: if this release fails
	// we can have unused destinations, but we can't have re-used IDs.
	if err := d.destinations.ReleaseID(dest); err != nil {
		return fmt.Errorf("remove binding: %s", err)
	}

	return nil
}

// Bindings lists known bindings.
//
// The returned slice is sorted.
func (d *Dispatcher) Bindings() ([]*Binding, error) {
	dests, err := d.destinations.List()
	if err != nil {
		return nil, fmt.Errorf("list destination IDs: %s", err)
	}

	var (
		key      bindingKey
		id       destinationID
		bindings []*Binding
		iter     = d.bindings.Iterate()
	)
	for iter.Next(&key, &id) {
		dest := dests[id]
		if dest == nil {
			return nil, fmt.Errorf("no destination for id %d", id)
		}

		bindings = append(bindings, newBindingFromBPF(dest.Label, &key))
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate bindings: %s", err)
	}

	sort.Slice(bindings, func(i, j int) bool {
		a, b := bindings[i], bindings[j]

		if a.Label != b.Label {
			return a.Label < b.Label
		}

		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}

		if a.Port != b.Port {
			return a.Port < b.Port
		}

		if c := bytes.Compare(a.Prefix.IP.To16(), b.Prefix.IP.To16()); c != 0 {
			return c < 0
		}

		aBits, _ := a.Prefix.Mask.Size()
		bBits, _ := b.Prefix.Mask.Size()
		return aBits < bBits
	})

	return bindings, nil
}

func checkMap(spec *ebpf.MapSpec, m *ebpf.Map) error {
	abi := m.ABI()
	if abi.Type != spec.Type {
		return fmt.Errorf("types differ")
	}
	if abi.KeySize != spec.KeySize {
		return fmt.Errorf("key sizes differ")
	}
	if abi.ValueSize != spec.ValueSize {
		return fmt.Errorf("value sizes differ")
	}

	// TODO: Check for flags?
	return nil
}

type SocketCookie uint64

func (c SocketCookie) String() string {
	return fmt.Sprintf("sk:%x", uint64(c))
}

func (d *Dispatcher) RegisterSocket(label string, conn syscall.Conn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("raw conn: %s", err)
	}

	dest, err := newDestinationFromConn(label, raw)
	if err != nil {
		return err
	}

	created, err := d.destinations.AddSocket(dest, raw)
	if err != nil {
		return fmt.Errorf("add socket: %s", err)
	}

	// TODO: Log and timestamp info messages
	if !created {
		fmt.Printf("Updated destination %s\n", dest)
	} else {
		fmt.Printf("Created destination %s\n", dest)
	}
	return nil
}
