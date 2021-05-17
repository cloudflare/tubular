package internal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/containernetworking/plugins/pkg/ns"
	"golang.org/x/sys/unix"
	"kernel.org/pub/linux/libs/security/libcap/cap"

	"code.cfops.it/sys/tubular/internal/lock"
	"code.cfops.it/sys/tubular/internal/log"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc "$CLANG" -makebase "$MAKEDIR" dispatcher ../ebpf/inet-kern.c -- -mcpu=v2 -nostdinc -Wall -Werror -I../ebpf/include

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

// CreateCapabilities are required to create a new dispatcher.
var CreateCapabilities = []cap.Value{cap.SYS_ADMIN, cap.NET_ADMIN}

// Dispatcher manipulates the socket dispatch data plane.
type Dispatcher struct {
	stateDir     *lock.File
	netns        ns.NetNS
	Path         string
	bindings     *ebpf.Map
	destinations *destinations
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

	netns, pinPath, err := openNetNS(netnsPath, bpfFsPath)
	if err != nil {
		return nil, err
	}
	defer closeOnError(netns)

	tempDir, err := ioutil.TempDir(filepath.Dir(pinPath), "tubular-*")
	if err != nil {
		return nil, fmt.Errorf("can't create temp directory: %s", err)
	}
	defer os.RemoveAll(tempDir)

	dir, err := lock.OpenLockedExclusive(tempDir)
	if err != nil {
		return nil, err
	}
	defer closeOnError(dir)

	var objs dispatcherObjects
	_, err = loadPatchedDispatcher(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: tempDir},
	})
	if err != nil {
		return nil, fmt.Errorf("load BPF: %s", err)
	}
	defer objs.dispatcherPrograms.Close()
	defer closeOnError(&objs.dispatcherMaps)

	if err := objs.Dispatcher.Pin(programPath(tempDir)); err != nil {
		return nil, fmt.Errorf("pin program: %s", err)
	}

	// The dispatcher is active after this call.
	link, err := link.AttachNetNs(int(netns.Fd()), objs.Dispatcher)
	if err != nil {
		return nil, fmt.Errorf("attach program to netns %s: %s", netns.Path(), err)
	}
	defer link.Close()

	if err := link.Pin(linkPath(tempDir)); err != nil {
		return nil, fmt.Errorf("can't pin link: %s", err)
	}

	if err := adjustPermissions(tempDir); err != nil {
		return nil, fmt.Errorf("adjust permissions: %s", err)
	}

	// Rename will succeed if pinPath doesn't exist or is an empty directory,
	// otherwise it will return an error. In that case tempDir is removed,
	// and the pinned link + program are closed, undoing any changes.
	if err := os.Rename(tempDir, pinPath); os.IsExist(err) || errors.Is(err, syscall.ENOTEMPTY) {
		return nil, fmt.Errorf("can't create dispatcher: %w", ErrLoaded)
	} else if err != nil {
		return nil, fmt.Errorf("can't create dispatcher: %s", err)
	}

	dests := newDestinations(objs.dispatcherMaps)
	return &Dispatcher{dir, netns, pinPath, objs.Bindings, dests, logger}, nil
}

func adjustPermissions(path string) error {
	const (
		// Allow user and group full access, and let others list the directory.
		dirMode os.FileMode = 0775
		// Allow user and group full access, and let others read the state.
		objMode os.FileMode = 0664
	)

	if err := os.Chmod(path, dirMode); err != nil {
		return err
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("read state entries: %s", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			return fmt.Errorf("change access mode: %q is a directory", entry.Name())
		}

		path := filepath.Join(path, entry.Name())
		if err := os.Chmod(path, objMode); err != nil {
			return err
		}
	}

	return nil
}

// OpenDispatcher loads an existing dispatcher from a namespace.
//
// Returns ErrNotLoaded if the dispatcher is not loaded yet.
func OpenDispatcher(logger log.Logger, netnsPath, bpfFsPath string, readOnly bool) (_ *Dispatcher, err error) {
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

	var dir *lock.File
	if readOnly {
		dir, err = lock.OpenLockedShared(pinPath)
	} else {
		dir, err = lock.OpenLockedExclusive(pinPath)
	}
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("%s: %w", bpfFsPath, ErrNotLoaded)
	} else if err != nil {
		return nil, fmt.Errorf("%s: %s", bpfFsPath, err)
	}
	defer closeOnError(dir)

	spec, err := loadPatchedDispatcher(nil, nil)
	if err != nil {
		return nil, err
	}

	if !readOnly {
		// DAC for BPF links and programs is currently broken: it's not possible
		// to acquire a read-only fd for them. So, for read-only mode we skip the
		// compatibility check. The rationale is that we need the compat check to
		// prevent incompatible modification to dispatcher state. Since this
		// isn't possible in read-only mode skipping the check is acceptable.
		// See https://lore.kernel.org/bpf/20210326160501.46234-1-lmb@cloudflare.com/#t
		var progs dispatcherProgramSpecs
		if err := spec.Assign(&progs); err != nil {
			return nil, err
		}

		link, err := link.LoadPinnedNetNs(linkPath(pinPath), nil)
		if err != nil {
			return nil, err
		}
		defer link.Close()

		prog, err := ebpf.LoadPinnedProgram(programPath(pinPath), nil)
		if err != nil {
			return nil, err
		}
		defer prog.Close()

		if err := isLinkCompatible(link, prog, progs.Dispatcher); err != nil {
			return nil, err
		}
	}

	var maps dispatcherMaps
	err = spec.LoadAndAssign(&maps, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
			LoadPinOptions: ebpf.LoadPinOptions{
				ReadOnly: readOnly,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("load BPF: %s", err)
	}
	defer closeOnError(&maps)

	dests := newDestinations(maps)
	return &Dispatcher{dir, netns, pinPath, maps.Bindings, dests, logger}, nil
}

func loadPatchedDispatcher(to interface{}, opts *ebpf.CollectionOptions) (*ebpf.CollectionSpec, error) {
	spec, err := loadDispatcher()
	if err != nil {
		return nil, err
	}

	var specs dispatcherSpecs
	if err := spec.Assign(&specs); err != nil {
		return nil, err
	}

	maxSockets := specs.Sockets.MaxEntries
	for _, m := range []*ebpf.MapSpec{
		specs.Destinations,
		specs.DestinationMetrics,
	} {
		if m.MaxEntries != maxSockets {
			return nil, fmt.Errorf("map %q has %d max entries instead of %d", m.Name, m.MaxEntries, maxSockets)
		}
	}

	specs.Destinations.KeySize = uint32(binary.Size(destinationKey{}))
	specs.Destinations.ValueSize = uint32(binary.Size(destinationAlloc{}))

	if to != nil {
		return spec, spec.LoadAndAssign(to, opts)
	}

	return spec, nil
}

// UpgradeDispatcher updates the datapath program for the given dispatcher.
//
// It doesn't remove old unused state.
//
// Returns the program ID of the new dispatcher or an error.
func UpgradeDispatcher(netnsPath, bpfFsPath string) (ebpf.ProgramID, error) {
	return upgradeDispatcher(netnsPath, bpfFsPath, link.NetNsLink.Update)
}

func upgradeDispatcher(netnsPath, bpfFsPath string, linkUpdate func(link.NetNsLink, *ebpf.Program) error) (ebpf.ProgramID, error) {
	netns, pinPath, err := openNetNS(netnsPath, bpfFsPath)
	if err != nil {
		return 0, err
	}
	defer netns.Close()

	dir, err := lock.OpenLockedExclusive(pinPath)
	if err != nil {
		return 0, fmt.Errorf("%s: %s", bpfFsPath, err)
	}
	defer dir.Close()

	var objs dispatcherObjects
	_, err = loadPatchedDispatcher(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinPath},
	})
	if err != nil {
		// We will fail here if the pinned maps are not compatible. This is
		// something we might have to solve in the future.
		return 0, fmt.Errorf("load dispatcher program: %s", err)
	}
	defer objs.Close()

	progInfo, err := objs.Dispatcher.Info()
	if err != nil {
		return 0, fmt.Errorf("get program info: %s", err)
	}
	progID, _ := progInfo.ID()

	nslink, err := link.LoadPinnedNetNs(linkPath(pinPath), nil)
	if err != nil {
		return 0, err
	}
	defer nslink.Close()

	progPath := programPath(pinPath)
	tmpPath := programUpgradePath(pinPath)
	if err := objs.Dispatcher.Pin(tmpPath); err != nil {
		return 0, fmt.Errorf("pin program: %s", err)
	}
	// Remove the temporary program pin if the update fails.
	defer os.Remove(tmpPath)

	// This is the start of the critical section. Do as little as possible in here.
	if err := linkUpdate(*nslink, objs.Dispatcher); err != nil {
		return 0, fmt.Errorf("update link: %s", err)
	}

	if err := os.Rename(tmpPath, progPath); err != nil {
		// At this point we are hosed: link and the pinned program disagree, so
		// the next OpenDispatcher call will fail. There isn't much we can do,
		// and if rename fails we probably have bigger fish to fry.
		return 0, fmt.Errorf("rename program: %s", err)
	}

	return progID, nil
}

// Close frees associated resources.
//
// It does not remove the dispatcher, see UnloadDispatcher.
func (d *Dispatcher) Close() error {
	// No need to lock the state, since we don't modify it here.
	if err := d.bindings.Close(); err != nil {
		return fmt.Errorf("can't close BPF objects: %s", err)
	}
	if err := d.destinations.Close(); err != nil {
		return fmt.Errorf("can't close destination IDs: %x", err)
	}
	if err := d.netns.Close(); err != nil {
		return fmt.Errorf("can't close netns handle: %s", err)
	}
	if err := d.stateDir.Close(); err != nil {
		return fmt.Errorf("can't close state directory handle: %s", err)
	}
	return nil
}

// UnloadDispatcher removes a dispatcher and its associated state.
//
// Returns ErrNotLoaded if the dispatcher state directory doesn't exist.
func UnloadDispatcher(netnsPath, bpfFsPath string) error {
	netns, pinPath, err := openNetNS(netnsPath, bpfFsPath)
	if err != nil {
		return err
	}
	defer netns.Close()

	dir, err := lock.OpenLockedExclusive(pinPath)
	if os.IsNotExist(err) {
		return fmt.Errorf("%s: %w", bpfFsPath, ErrNotLoaded)
	} else if err != nil {
		return fmt.Errorf("%s: %s", bpfFsPath, err)
	}
	defer dir.Close()

	if err := os.RemoveAll(pinPath); err != nil {
		return fmt.Errorf("remove pinned state: %s", err)
	}

	return nil
}

// Program returns the active dispatcher program.
//
// The caller must call Program.Close().
func (dp *Dispatcher) Program() (*ebpf.Program, error) {
	return ebpf.LoadPinnedProgram(programPath(dp.Path), nil)
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
func (d *Dispatcher) AddBinding(bind *Binding) error {
	dest := newDestinationFromBinding(bind)

	if bind.Prefix.IP.Is4in6() {
		return fmt.Errorf("prefix cannot be v4-mapped v6: %v", bind.Prefix)
	}

	key := newBindingKey(bind)

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
	key := newBindingKey(bind)

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
	d.stateDir.Lock()
	defer d.stateDir.Unlock()

	want := make(map[bindingKey]string)
	for _, bind := range bindings {
		key := newBindingKey(bind)

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
		if err := d.AddBinding(bind); err != nil {
			return false, fmt.Errorf("add binding %s: %s", bind, err)
		}
		d.log.Log("added binding", bind)
	}

	for _, bind := range removed {
		if err := d.RemoveBinding(bind); err != nil {
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
	d.stateDir.Lock()
	defer d.stateDir.Unlock()

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

	d.stateDir.Lock()
	defer d.stateDir.Unlock()

	created, err = d.destinations.AddSocket(dest, conn)
	if err != nil {
		return nil, false, fmt.Errorf("add socket: %s", err)
	}

	return
}

// Metrics contain counters generated by the data plane.
type Metrics struct {
	Destinations map[Destination]DestinationMetrics
	Bindings     map[Destination]uint64
}

// Metrics returns current counters from the data plane.
func (d *Dispatcher) Metrics() (*Metrics, error) {
	d.stateDir.Lock()
	defer d.stateDir.Unlock()

	destMetrics, err := d.destinations.Metrics()
	if err != nil {
		return nil, fmt.Errorf("destination metrics: %s", err)
	}

	bindings, err := d.Bindings()
	if err != nil {
		return nil, fmt.Errorf("bindings metrics: %s", err)
	}

	bindingMetrics := bindings.metrics()

	return &Metrics{destMetrics, bindingMetrics}, nil
}

// Destinations returns a set of existing destinations, i.e. sockets and labels.
func (d *Dispatcher) Destinations() ([]Destination, map[Destination]SocketCookie, error) {
	d.stateDir.Lock()
	defer d.stateDir.Unlock()

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
