package internal

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc "$CLANG" -makebase "$MAKEDIR" dispatcher ../ebpf/inet-kern.c -- -mcpu=v2 -O2 -g -nostdinc -Wall -Werror -I../ebpf/include

// Errors returned by the Dispatcher.
var (
	ErrLoaded    = errors.New("dispatcher already loaded")
	ErrNotLoaded = errors.New("dispatcher not loaded")
)

// Dispatcher manipulates the socket dispatch data plane.
type Dispatcher struct {
	netns *netns
	link  link.Link
	Path  string
	bpf   dispatcherObjects
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

	return newDispatcher(netns, coll, pinPath)
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

	if _, err := os.Stat(pinPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("%s: %w", netnsPath, ErrNotLoaded)
	} else if err != nil {
		return nil, fmt.Errorf("%s: %s", netnsPath, err)
	}

	loadedMaps := make(map[string]*ebpf.Map)
	for name, mapSpec := range spec.Maps {
		m, err := ebpf.LoadPinnedMap(filepath.Join(pinPath, name))
		if err != nil {
			return nil, fmt.Errorf("can't load pinned map %s: %s", name, err)
		}

		if err := checkMap(mapSpec, m); err != nil {
			return nil, fmt.Errorf("pinned map %s is incompatible: %s", name, err)
		}

		loadedMaps[name] = m
	}

	if err := spec.RewriteMaps(loadedMaps); err != nil {
		return nil, fmt.Errorf("can't use pinned maps: %s", err)
	}

	coll, err = ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("can't load BPF: %s", err)
	}

	// RewriteMaps removes maps from spec, so we have to
	// add them back here.
	coll.Maps = loadedMaps

	return newDispatcher(netns, coll, pinPath)
}

func newDispatcher(netns *netns, coll *ebpf.Collection, bpfPath string) (_ *Dispatcher, err error) {
	closeOnError := func(c io.Closer) {
		if err != nil {
			c.Close()
		}
	}

	var bpf dispatcherObjects
	if err := coll.Assign(&bpf); err != nil {
		return nil, fmt.Errorf("can't assign objects: %s", err)
	}
	defer closeOnError(&bpf)

	linkPath := filepath.Join(bpfPath, "link")
	attach, err := link.LoadPinnedRawLink(linkPath)
	if err != nil {
		attach, err = netns.AttachProgram(bpf.ProgramDispatcher)
		if err != nil {
			return nil, err
		}
		defer closeOnError(attach)

		if err := attach.Pin(linkPath); err != nil {
			return nil, fmt.Errorf("can't pin link: %s", err)
		}
	}

	return &Dispatcher{netns, attach, bpfPath, bpf}, nil
}

// Close frees associated resources.
//
// It does not remove the dispatcher, see Unload for that.
func (d *Dispatcher) Close() error {
	if err := d.link.Close(); err != nil {
		return fmt.Errorf("can't close link: %s", err)
	}
	if err := d.bpf.Close(); err != nil {
		return fmt.Errorf("can't close BPF objects: %s", err)
	}
	if err := d.netns.Close(); err != nil {
		return fmt.Errorf("can't close netns handle: %s", err)
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

type Protocol uint8

const (
	tcpProto Protocol = unix.IPPROTO_TCP
	udpProto Protocol = unix.IPPROTO_UDP
)

func (p Protocol) network() string {
	switch p {
	case tcpProto:
		return "tcp"
	case udpProto:
		return "udp"
	default:
		return "unknown"
	}
}

type srvname [255]byte

func newSrvname(name string) (*srvname, error) {
	var res srvname
	if n := copy(res[:], name); n != len(name) {
		return nil, fmt.Errorf("name truncated to %d bytes", n)
	}
	return &res, nil
}

func (sn *srvname) String() string {
	inLen := bytes.IndexByte([]byte(sn[:]), 0)
	if inLen == -1 {
		return ""
	}
	return string(sn[:inLen])
}

func (d *Dispatcher) AddBinding(service string, proto Protocol, prefix *net.IPNet, port uint16) error {
	key, err := newBindingKey(prefix, proto, port)
	if err != nil {
		return err
	}

	existingSrvname := new(srvname)
	if err := d.bpf.MapBindMap.Lookup(key, existingSrvname); err == nil {
		if service == existingSrvname.String() {
			// TODO: We could also turn this into a no-op?
			return fmt.Errorf("create binding: already bound to %q", service)
		}
	}

	srvname, err := newSrvname(service)
	if err != nil {
		return err
	}

	err = d.bpf.MapBindMap.Update(key, srvname, 0)
	if err != nil {
		return fmt.Errorf("create binding: %s", err)
	}

	return nil
}

func (d *Dispatcher) RemoveBinding(proto Protocol, prefix *net.IPNet, port uint16) error {
	key, err := newBindingKey(prefix, proto, port)
	if err != nil {
		return err
	}

	if err := d.bpf.MapBindMap.Delete(key); err != nil {
		return fmt.Errorf("remove binding: %s", err)
	}

	return nil
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
