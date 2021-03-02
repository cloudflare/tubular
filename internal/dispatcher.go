package internal

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/containernetworking/plugins/pkg/ns"
	"golang.org/x/sys/unix"

	"code.cfops.it/sys/tubular/internal/lock"
	"code.cfops.it/sys/tubular/internal/log"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc "$CLANG" -makebase "$MAKEDIR" dispatcher ../ebpf/inet-kern.c -- -mcpu=v2 -O2 -g -nostdinc -Wall -Werror -I../ebpf/include

// Errors returned by the Dispatcher.
var (
	ErrLoaded            = errors.New("dispatcher already loaded")
	ErrNotLoaded         = errors.New("dispatcher not loaded")
	ErrNotSocket         = syscall.ENOTSOCK
	ErrBadSocketDomain   = syscall.EPFNOSUPPORT
	ErrBadSocketType     = syscall.ESOCKTNOSUPPORT
	ErrBadSocketProtocol = syscall.EPROTONOSUPPORT
	ErrBadSocketState    = syscall.EBADFD
)

// TODO: Remove this once https://github.com/cilium/ebpf/pull/195 is merged.
type dispatcherMaps struct {
	Bindings           *ebpf.Map `ebpf:"bindings"`
	DestinationMetrics *ebpf.Map `ebpf:"destination_metrics"`
	Sockets            *ebpf.Map `ebpf:"sockets"`
}

func (dm *dispatcherMaps) Close() error {
	for _, closer := range []io.Closer{
		dm.Bindings,
		dm.DestinationMetrics,
		dm.Sockets,
	} {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Dispatcher manipulates the socket dispatch data plane.
type Dispatcher struct {
	stateMu      sync.Locker
	netns        ns.NetNS
	link         *link.NetNsLink
	Path         string
	bindings     *ebpf.Map
	destinations *destinations
	dir          *os.File
	log          log.Logger
}

// CreateDispatcher loads the dispatcher into a network namespace.
//
// Returns ErrLoaded if the namespace already has the dispatcher enabled.
func CreateDispatcher(logger log.Logger, netnsPath, bpfFsPath string) (_ *Dispatcher, err error) {
	closeOnError := func(c io.Closer) {
		if err != nil {
			c.Close()
		}
	}

	specs, err := newDispatcherSpecs()
	if err != nil {
		return nil, err
	}

	netns, pinPath, err := openNetNS(netnsPath, bpfFsPath)
	if err != nil {
		return nil, err
	}
	defer closeOnError(netns)

	tempDir, err := ioutil.TempDir(filepath.Dir(string(pinPath)), "tubular-*")
	if err != nil {
		return nil, fmt.Errorf("can't create temp directory: %s", err)
	}
	defer os.RemoveAll(tempDir)

	dir, err := os.Open(tempDir)
	if err != nil {
		return nil, err
	}
	defer closeOnError(dir)

	stateMu, err := lock.Exclusive(dir)
	if err != nil {
		return nil, fmt.Errorf("can't lock state directory: %s", err)
	}

	stateMu.Lock()
	defer stateMu.Unlock()

	bpf, err := specs.Load(&ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: tempDir},
	})
	if err != nil {
		return nil, fmt.Errorf("load BPF: %s", err)
	}
	defer bpf.Close()

	dests, err := newDestinations(dispatcherMaps{
		bpf.MapBindings,
		bpf.MapDestinationMetrics,
		bpf.MapSockets,
	}, tempDir)
	if err != nil {
		return nil, err
	}
	defer closeOnError(dests)

	if err := bpf.ProgramDispatcher.Pin(programPath(tempDir)); err != nil {
		return nil, fmt.Errorf("pin program: %s", err)
	}

	// The dispatcher is active after this call. Since we've not taken any
	// lock, this can lead to two programs being active. We rely on the socket
	// lookup semantics to prevent this being an issue.
	link, err := link.AttachNetNs(int(netns.Fd()), bpf.ProgramDispatcher)
	if err != nil {
		return nil, fmt.Errorf("attach program to netns %s: %s", netns.Path(), err)
	}
	defer closeOnError(link)

	if err := link.Pin(linkPath(tempDir)); err != nil {
		return nil, fmt.Errorf("can't pin link: %s", err)
	}

	mapBindings, err := bpf.MapBindings.Clone()
	if err != nil {
		return nil, fmt.Errorf("can't clone bindings map: %s", err)
	}

	// Rename will succeed if pinPath doesn't exist or is an empty directory,
	// otherwise it will return an error. In that case tempDir is removed,
	// and the pinned link + program are closed, undoing any changes.
	if err := os.Rename(tempDir, pinPath); os.IsExist(err) || errors.Is(err, syscall.ENOTEMPTY) {
		return nil, fmt.Errorf("can't create dispatcher: %w", ErrLoaded)
	} else if err != nil {
		return nil, fmt.Errorf("can't create dispatcher: %s", err)
	}

	return &Dispatcher{stateMu, netns, link, pinPath, mapBindings, dests, dir, logger}, nil
}

// OpenDispatcher loads an existing dispatcher from a namespace.
//
// Returns ErrNotLoaded if the dispatcher is not loaded yet.
func OpenDispatcher(logger log.Logger, netnsPath, bpfFsPath string) (_ *Dispatcher, err error) {
	closeOnError := func(c io.Closer) {
		if err != nil {
			c.Close()
		}
	}

	netns, pinPath, err := openNetNS(netnsPath, bpfFsPath)
	if err != nil {
		return nil, err
	}
	defer closeOnError(netns)

	dir, err := os.Open(pinPath)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("%s: %w", netnsPath, ErrNotLoaded)
	} else if err != nil {
		return nil, fmt.Errorf("%s: %s", netnsPath, err)
	}
	defer closeOnError(dir)

	stateMu, err := lock.Exclusive(dir)
	if err != nil {
		return nil, fmt.Errorf("can't lock state directory: %s", err)
	}

	stateMu.Lock()
	defer stateMu.Unlock()

	specs, err := newDispatcherSpecs()
	if err != nil {
		return nil, err
	}

	link, err := link.LoadPinnedNetNs(linkPath(pinPath))
	if err != nil {
		return nil, fmt.Errorf("load link: %s", err)
	}
	defer closeOnError(link)

	prog, err := ebpf.LoadPinnedProgram(programPath(pinPath))
	if err != nil {
		return nil, fmt.Errorf("load dispatcher: %s", err)
	}
	defer prog.Close()

	if compat, err := isLinkCompatible(link, prog, specs.ProgramDispatcher); err != nil {
		return nil, fmt.Errorf("check dispatcher compatibility: %s", err)
	} else if !compat {
		return nil, fmt.Errorf("loaded dispatcher is incompatible")
	}

	var maps dispatcherMaps
	err = specs.CollectionSpec().LoadAndAssign(&maps, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinPath},
	})
	if err != nil {
		return nil, fmt.Errorf("load BPF: %s", err)
	}
	defer maps.Close()

	dests, err := newDestinations(maps, pinPath)
	if err != nil {
		return nil, err
	}
	defer closeOnError(dests)

	mapBindings, err := maps.Bindings.Clone()
	if err != nil {
		return nil, fmt.Errorf("can't clone bindings map: %s", err)
	}

	return &Dispatcher{stateMu, netns, link, pinPath, mapBindings, dests, dir, logger}, nil
}

// Close frees associated resources.
//
// It does not remove the dispatcher, see Unload for that.
func (d *Dispatcher) Close() error {
	// No need to lock the state, since we don't modify it here.
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
	if err := d.dir.Close(); err != nil {
		return fmt.Errorf("can't close state directory handle: %s", err)
	}
	return nil
}

// Unload removes the dispatcher.
//
// It isn't necessary to call Close() afterwards.
func (d *Dispatcher) Unload() error {
	// We have to Close after Unlock, since it panics otherwise.
	defer d.Close()

	d.stateMu.Lock()
	defer d.stateMu.Unlock()

	if err := os.RemoveAll(d.Path); err != nil {
		return fmt.Errorf("can't remove pinned state: %s", err)
	}

	return nil
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

func (p *Protocol) UnmarshalText(text []byte) error {
	switch v := string(text); v {
	case "tcp":
		*p = TCP
	case "udp":
		*p = UDP
	default:
		return fmt.Errorf("unknown protocol %q", v)
	}
	return nil
}

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
func (d *Dispatcher) AddBinding(bind *Binding) (err error) {
	d.stateMu.Lock()
	defer d.stateMu.Unlock()

	return d.addBinding(bind)
}

func (d *Dispatcher) addBinding(bind *Binding) (err error) {
	dest := newDestinationFromBinding(bind)

	key, err := newBindingKey(bind)
	if err != nil {
		return err
	}

	var old bindingValue
	var releaseOldID bool
	if err := d.bindings.Lookup(key, &old); err == nil {
		// Since the LPM trie will return the "best" match we have to make sure
		// that the prefix length matches to ensure that we're replacing a binding,
		// not just installing a more specific one.
		releaseOldID = old.PrefixLen == key.PrefixLen
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("lookup binding: %s", err)
	}

	id, err := d.destinations.Acquire(dest)
	if err != nil {
		return fmt.Errorf("acquire destination: %s", err)
	}

	new := bindingValue{id, key.PrefixLen}
	err = d.bindings.Update(key, &new, 0)
	if err != nil {
		_ = d.destinations.Release(dest)
		return fmt.Errorf("create binding: %s", err)
	}

	if releaseOldID {
		_ = d.destinations.ReleaseByID(old.ID)
	}

	return nil
}

// RemoveBinding stops redirecting traffic for a given protocol, prefix and port.
//
// Returns an error if the binding doesn't exist.
func (d *Dispatcher) RemoveBinding(bind *Binding) error {
	d.stateMu.Lock()
	defer d.stateMu.Unlock()

	return d.removeBinding(bind)
}

func (d *Dispatcher) removeBinding(bind *Binding) error {
	key, err := newBindingKey(bind)
	if err != nil {
		return err
	}

	var existing bindingValue
	if err := d.bindings.Lookup(key, &existing); err != nil {
		return fmt.Errorf("remove binding: lookup destination: %s", err)
	}

	dest := newDestinationFromBinding(bind)
	if !d.destinations.HasID(dest, existing.ID) {
		return fmt.Errorf("remove binding: destination mismatch")
	}

	if err := d.bindings.Delete(key); err != nil {
		return fmt.Errorf("remove binding: %s", err)
	}

	// We err on the side of caution here: if this release fails
	// we can have unused destinations, but we can't have re-used IDs.
	if err := d.destinations.Release(dest); err != nil {
		return fmt.Errorf("remove binding: %s", err)
	}

	return nil
}

// ReplaceBindings changes the currently active bindings to a new set.
//
// It is conceptually identical to repeatedly calling AddBinding and RemoveBinding
// and therefore not atomic: the function may return without applying all changes.
//
// Returns a boolean indicating whether any changes were made.
func (d *Dispatcher) ReplaceBindings(bindings Bindings) (bool, error) {
	d.stateMu.Lock()
	defer d.stateMu.Unlock()

	want := make(map[bindingKey]string)
	for _, bind := range bindings {
		key, err := newBindingKey(bind)
		if err != nil {
			return false, fmt.Errorf("binding %s: %s", bind, err)
		}

		if label := want[*key]; label != "" {
			return false, fmt.Errorf("duplicate binding %s: already assigned to %s", bind, label)
		}

		want[*key] = bind.Label
	}

	have := make(map[bindingKey]string)
	err := d.iterBindings(func(key bindingKey, label string) {
		have[key] = label
	})
	if err != nil {
		return false, fmt.Errorf("get existing bindings: %s", err)
	}

	// TUBE-45: we should add bindings in most to least, and remove them
	// in least to most specific order. Instead, we can replace this code
	// with an atomic map swap in the future.
	added, removed := diffBindings(have, want)

	for _, bind := range added {
		if err := d.addBinding(bind); err != nil {
			return false, fmt.Errorf("add binding %s: %s", bind, err)
		}
		d.log.Log("added binding", bind)
	}

	for _, bind := range removed {
		if err := d.removeBinding(bind); err != nil {
			return false, fmt.Errorf("remove binding %s: %s", bind, err)
		}
		d.log.Log("removed binding", bind)
	}

	return len(added) > 0 || len(removed) > 0, nil
}

func (d *Dispatcher) iterBindings(fn func(bindingKey, string)) error {
	// Must be called with the state lock held.

	dests, err := d.destinations.List()
	if err != nil {
		return fmt.Errorf("list destination IDs: %s", err)
	}

	var (
		key   bindingKey
		value bindingValue
		iter  = d.bindings.Iterate()
	)
	for iter.Next(&key, &value) {
		dest := dests[value.ID]
		if dest == nil {
			return fmt.Errorf("no destination for id %d", value.ID)
		}

		fn(key, dest.Label)
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate bindings: %s", err)
	}

	return nil
}

// Bindings lists known bindings.
func (d *Dispatcher) Bindings() (Bindings, error) {
	d.stateMu.Lock()
	defer d.stateMu.Unlock()

	var bindings Bindings
	err := d.iterBindings(func(key bindingKey, label string) {
		bindings = append(bindings, newBindingFromBPF(label, &key))
	})
	if err != nil {
		return nil, err
	}

	return bindings, nil
}

type SocketCookie uint64

func (c SocketCookie) String() string {
	if c == 0 {
		// Socket cookies are always allocated starting at 1.
		return "sk:-"
	}
	return fmt.Sprintf("sk:%x", uint64(c))
}

// RegisterSocket adds a socket with the given label.
//
// The socket receives traffic for all Bindings that share the same label,
// L3 and L4 protocol.
//

// Returns the Destination with which the socket was registered, and a boolean
// indicating whether the Destination was created or updated, or an error.
func (d *Dispatcher) RegisterSocket(label string, conn syscall.Conn) (dest *Destination, created bool, _ error) {
	dest, err := newDestinationFromConn(label, conn)
	if err != nil {
		return nil, false, err
	}

	d.stateMu.Lock()
	defer d.stateMu.Unlock()

	created, err = d.destinations.AddSocket(dest, conn)
	if err != nil {
		return nil, false, fmt.Errorf("add socket: %s", err)
	}

	return
}

// Metrics contain counters generated by the data plane.
type Metrics struct {
	Destinations map[Destination]DestinationMetrics
}

// Metrics returns current counters from the data plane.
func (d *Dispatcher) Metrics() (*Metrics, error) {
	d.stateMu.Lock()
	defer d.stateMu.Unlock()

	destMetrics, err := d.destinations.Metrics()
	if err != nil {
		return nil, fmt.Errorf("destination metrics: %s", err)
	}

	return &Metrics{destMetrics}, nil
}

// Destinations returns a set of existing destinations, i.e. sockets and labels.
func (d *Dispatcher) Destinations() ([]Destination, map[Destination]SocketCookie, error) {
	d.stateMu.Lock()
	defer d.stateMu.Unlock()

	destsByID, err := d.destinations.List()
	if err != nil {
		return nil, nil, fmt.Errorf("list destinations: %s", err)
	}

	socketsByID, err := d.destinations.Sockets()
	if err != nil {
		return nil, nil, fmt.Errorf("list sockets: %s", err)
	}

	dests := make([]Destination, 0, len(destsByID))
	cookies := make(map[Destination]SocketCookie)
	for id, dest := range destsByID {
		dests = append(dests, *dest)
		cookies[*dest] = socketsByID[id]
	}
	return dests, cookies, nil
}
