package internal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
)

// destinationID is a numeric identifier for a destination.
// 0 is not a valid ID.
type destinationID uint32

// systemd supports names of up to 255 bytes, match the limit.
type label [255]byte

func (lbl *label) String() string {
	end := bytes.IndexByte((*lbl)[:], 0)
	if end == -1 {
		end = len(*lbl)
	}

	return string((*lbl)[:end])
}

type destinationKey struct {
	Label    label
	Domain   Domain
	Protocol Protocol
}

func newDestinationKey(dest *Destination) (*destinationKey, error) {
	key := &destinationKey{
		Domain:   dest.Domain,
		Protocol: dest.Protocol,
	}

	if dest.Label == "" {
		return nil, fmt.Errorf("label is empty")
	}
	if strings.ContainsRune(dest.Label, 0) {
		return nil, fmt.Errorf("label contains null byte")
	}
	if max := len(key.Label); len(dest.Label) > max {
		return nil, fmt.Errorf("label exceeds maximum length of %d bytes", max)
	}

	copy(key.Label[:], dest.Label)
	return key, nil
}

func (dkey *destinationKey) String() string {
	return fmt.Sprintf("%s:%s:%s", dkey.Label, dkey.Domain, dkey.Protocol)
}

type destinationAlloc struct {
	ID    destinationID
	Count uint32
}

// A Destination receives traffic from a Binding.
//
// It is implicitly created when registering a socket with a Dispatcher.
type Destination struct {
	Label    string
	Domain   Domain
	Protocol Protocol
	Socket   SocketCookie
}

func newDestinationFromBinding(bind *Binding) *Destination {
	domain := AF_INET
	if bind.Prefix.IP.To4() == nil {
		domain = AF_INET6
	}

	return &Destination{bind.Label, domain, bind.Protocol, 0}
}

func (dest *Destination) String() string {
	return fmt.Sprintf("%s:%s:%s->%s", dest.Domain, dest.Protocol, dest.Label, dest.Socket)
}

type destinations struct {
	allocs  *ebpf.Map
	sockets *ebpf.Map
}

var destinationsSpec = &ebpf.MapSpec{
	Name:       "tube_dest_ids",
	Type:       ebpf.Hash,
	KeySize:    uint32(binary.Size(destinationKey{})),
	ValueSize:  uint32(binary.Size(destinationAlloc{})),
	MaxEntries: 512,
}

func newDestinations(bpf *dispatcherObjects) (*destinations, error) {
	ids, err := ebpf.NewMap(destinationsSpec)
	if err != nil {
		return nil, fmt.Errorf("create destinations: %s", err)
	}

	return &destinations{ids, bpf.MapSockets}, nil
}

func createDestinations(bpf *dispatcherObjects, path string) (*destinations, error) {
	lbls, err := newDestinations(bpf)
	if err != nil {
		return nil, err
	}

	if err := lbls.allocs.Pin(path); err != nil {
		return nil, fmt.Errorf("create destinations: %s", err)
	}

	return lbls, nil
}

func openDestinations(bpf *dispatcherObjects, path string) (*destinations, error) {
	ids, err := ebpf.LoadPinnedMap(path)
	if err != nil {
		return nil, fmt.Errorf("can't load pinned destinations: %s", err)
	}

	if err := checkMap(destinationsSpec, ids); err != nil {
		ids.Close()
		return nil, fmt.Errorf("pinned destinations: %s", err)
	}

	return &destinations{ids, bpf.MapSockets}, nil
}

func (dests *destinations) Close() error {
	if err := dests.allocs.Close(); err != nil {
		return err
	}
	return dests.sockets.Close()
}

func (dests *destinations) AddSocket(dest *Destination, conn syscall.RawConn) (created bool, err error) {
	key, err := newDestinationKey(dest)
	if err != nil {
		return false, err
	}

	alloc, err := dests.getAllocation(key)
	if err != nil {
		return false, err
	}

	var opErr error
	err = conn.Control(func(fd uintptr) {
		opErr = dests.sockets.Update(alloc.ID, uint64(fd), ebpf.UpdateExist)
		if errors.Is(opErr, ebpf.ErrKeyNotExist) {
			created = true
			opErr = dests.sockets.Update(alloc.ID, uint64(fd), ebpf.UpdateNoExist)
		}
	})
	if err != nil {
		return false, fmt.Errorf("access fd: %s", err)
	}
	if opErr != nil {
		return false, fmt.Errorf("map update failed: %s", opErr)
	}

	return
}

func (dests *destinations) HasID(dest *Destination, want destinationID) bool {
	key, err := newDestinationKey(dest)
	if err != nil {
		return false
	}

	var alloc destinationAlloc
	err = dests.allocs.Lookup(key, &alloc)
	if err != nil {
		return false
	}

	return alloc.ID == want
}

func (dests *destinations) AcquireID(dest *Destination) (destinationID, error) {
	key, err := newDestinationKey(dest)
	if err != nil {
		return 0, err
	}

	alloc, err := dests.getAllocation(key)
	if err != nil {
		return 0, fmt.Errorf("get allocation for %v: %s", key, err)
	}

	alloc.Count++
	if alloc.Count == 0 {
		return 0, fmt.Errorf("acquire binding %v: counter overflow", key)
	}

	if err := dests.allocs.Update(key, alloc, ebpf.UpdateExist); err != nil {
		return 0, fmt.Errorf("acquire binding %v: %s", key, err)
	}

	return alloc.ID, nil
}

func (dests *destinations) allocationInUse(alloc *destinationAlloc) bool {
	if alloc.Count > 0 {
		// There is at least one outstanding user of this ID.
		return true
	}

	// There is no outstanding user, but we might need the ID to refer to an
	// existing socket. Do a lookup in our sockmap to find out.
	var unused SocketCookie
	err := dests.sockets.Lookup(alloc.ID, &unused)
	return !errors.Is(err, ebpf.ErrKeyNotExist)
}

// getAllocation returns an existing allocation, or creates a new one with an
// unused ID.
func (dests *destinations) getAllocation(key *destinationKey) (*destinationAlloc, error) {
	alloc := new(destinationAlloc)
	if err := dests.allocs.Lookup(key, alloc); err == nil {
		return alloc, nil
	}

	var (
		unused destinationKey
		ids    []destinationID
		iter   = dests.allocs.Iterate()
	)
	for iter.Next(&unused, alloc) {
		if dests.allocationInUse(alloc) {
			ids = append(ids, alloc.ID)
		}
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate allocations: %s", err)
	}

	id := destinationID(1)
	if len(ids) > 0 {
		sort.Slice(ids, func(i, j int) bool {
			return ids[i] < ids[j]
		})

		for _, allocatedID := range ids {
			if id < allocatedID {
				break
			}

			id = allocatedID + 1
			if id < allocatedID {
				return nil, fmt.Errorf("allocate destination: ran out of ids")
			}
		}
	}

	alloc = &destinationAlloc{ID: id}

	// This may replace an unused-but-not-deleted allocation.
	if err := dests.allocs.Update(key, alloc, ebpf.UpdateAny); err != nil {
		return nil, fmt.Errorf("allocate destination: %s", err)
	}

	return alloc, nil
}

func (dests *destinations) ReleaseID(dest *Destination) error {
	key, err := newDestinationKey(dest)
	if err != nil {
		return err
	}

	var alloc destinationAlloc
	err = dests.allocs.Lookup(key, &alloc)
	if err != nil {
		return fmt.Errorf("release id for %s: %s", key, err)
	}

	if alloc.Count == 0 {
		return fmt.Errorf("release id: underflow")
	}

	alloc.Count--
	if dests.allocationInUse(&alloc) {
		if err = dests.allocs.Update(key, &alloc, ebpf.UpdateExist); err != nil {
			return fmt.Errorf("release id for %s: %s", key, err)
		}
		return nil
	}

	// There are no more references, and no socket. We can release the allocation.
	if err = dests.allocs.Delete(key); err != nil {
		return fmt.Errorf("delete allocation: %s", err)
	}
	return nil
}

func (dests *destinations) List() (map[destinationID]*Destination, error) {
	var (
		key    destinationKey
		alloc  destinationAlloc
		result = make(map[destinationID]*Destination)
		iter   = dests.allocs.Iterate()
	)
	for iter.Next(&key, &alloc) {
		var cookie SocketCookie
		err := dests.sockets.Lookup(alloc.ID, &cookie)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			if alloc.Count == 0 {
				continue
			}
		} else if err != nil {
			return nil, fmt.Errorf("lookup cookie for id %d: %s", alloc.ID, err)
		}

		result[alloc.ID] = &Destination{
			key.Label.String(),
			key.Domain,
			key.Protocol,
			cookie,
		}
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate allocations: %s", err)
	}
	return result, nil
}
