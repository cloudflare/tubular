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
	"golang.org/x/sys/unix"
)

// destinationID is a numeric identifier for a destination.
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

func newDestinationFromFd(label string, fd uintptr) (*Destination, error) {
	var stat unix.Stat_t
	err := unix.Fstat(int(fd), &stat)
	if err != nil {
		return nil, fmt.Errorf("fstat: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return nil, fmt.Errorf("fd is not a socket: %w", ErrNotSocket)
	}

	domain, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_DOMAIN)
	if err != nil {
		return nil, fmt.Errorf("get SO_DOMAIN: %w", err)
	}

	sotype, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil {
		return nil, fmt.Errorf("get SO_TYPE: %w", err)
	}

	proto, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PROTOCOL)
	if err != nil {
		return nil, fmt.Errorf("get SO_PROTOCOL: %w", err)
	}

	acceptConn, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
	if err != nil {
		return nil, fmt.Errorf("get SO_ACCEPTCONN: %w", err)
	}
	listening := (acceptConn == 1)

	unconnected := false
	if _, err = unix.Getpeername(int(fd)); err != nil {
		if !errors.Is(err, unix.ENOTCONN) {
			return nil, fmt.Errorf("getpeername: %w", err)
		}
		unconnected = true
	}

	cookie, err := unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil {
		return nil, fmt.Errorf("get SO_COOKIE: %w", err)
	}

	if domain != unix.AF_INET && domain != unix.AF_INET6 {
		return nil, fmt.Errorf("unsupported socket domain %v: %w", domain, ErrBadSocketDomain)
	}
	if sotype != unix.SOCK_STREAM && sotype != unix.SOCK_DGRAM {
		return nil, fmt.Errorf("unsupported socket type %v: %w", sotype, ErrBadSocketType)
	}
	if sotype == unix.SOCK_STREAM && proto != unix.IPPROTO_TCP {
		return nil, fmt.Errorf("unsupported stream socket protocol %v: %w", proto, ErrBadSocketProtocol)
	}
	if sotype == unix.SOCK_DGRAM && proto != unix.IPPROTO_UDP {
		return nil, fmt.Errorf("unsupported packet socket protocol %v: %w", proto, ErrBadSocketDomain)
	}
	if sotype == unix.SOCK_STREAM && !listening {
		return nil, fmt.Errorf("stream socket not listening: %w", ErrBadSocketState)
	}
	if sotype == unix.SOCK_DGRAM && !unconnected {
		return nil, fmt.Errorf("packet socket is connected: %w", ErrBadSocketState)
	}

	// Reject dual-stack sockets
	if domain == unix.AF_INET6 {
		v6only, err := unix.GetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_V6ONLY)
		if err != nil {
			return nil, fmt.Errorf("getsockopt(IPV6_V6ONLY): %w", err)
		}
		if v6only != 1 {
			return nil, fmt.Errorf("unsupported dual-stack ipv6 socket (not v6only): %w", ErrBadSocketState)
		}
	}

	return &Destination{
		label,
		Domain(domain),
		Protocol(proto),
		SocketCookie(cookie),
	}, nil
}

func newDestinationFromConn(label string, conn syscall.RawConn) (*Destination, error) {
	var (
		dest  *Destination
		opErr error
	)
	err := conn.Control(func(fd uintptr) {
		dest, opErr = newDestinationFromFd(label, fd)
	})
	if err != nil {
		return nil, fmt.Errorf("access fd: %s", err)
	}
	if opErr != nil {
		return nil, opErr
	}

	return dest, nil
}

func (dest *Destination) String() string {
	return fmt.Sprintf("%s:%s:%s->%s", dest.Domain, dest.Protocol, dest.Label, dest.Socket)
}

type destinations struct {
	allocs  *ebpf.Map
	sockets *ebpf.Map
	metrics *ebpf.Map
	maxID   destinationID
}

var destinationsSpec = &ebpf.MapSpec{
	Name:       "destinations",
	Type:       ebpf.Hash,
	KeySize:    uint32(binary.Size(destinationKey{})),
	ValueSize:  uint32(binary.Size(destinationAlloc{})),
	MaxEntries: 512,
}

func newDestinations(maps dispatcherMaps, pinPath string) (*destinations, error) {
	maxEntries := maps.Sockets.MaxEntries()
	if destMax := maps.DestinationMetrics.MaxEntries(); destMax != maxEntries {
		return nil, fmt.Errorf("socket and metrics map size doesn't match: %d != %d", maxEntries, destMax)
	}

	spec := destinationsSpec.Copy()
	if pinPath != "" {
		spec.Pinning = ebpf.PinByName
	}

	allocs, err := ebpf.NewMapWithOptions(spec, ebpf.MapOptions{PinPath: pinPath})
	if err != nil {
		return nil, fmt.Errorf("create destinations map: %s", err)
	}

	mapSockets, err := maps.Sockets.Clone()
	if err != nil {
		allocs.Close()
		return nil, fmt.Errorf("can't clone sockets map: %s", err)
	}

	mapDestinationMetrics, err := maps.DestinationMetrics.Clone()
	if err != nil {
		allocs.Close()
		mapSockets.Close()
		return nil, fmt.Errorf("can't clone destination metrics map: %s", err)
	}

	return &destinations{
		allocs,
		mapSockets,
		mapDestinationMetrics,
		destinationID(maxEntries),
	}, nil
}

func (dests *destinations) Close() error {
	if err := dests.allocs.Close(); err != nil {
		return err
	}
	if err := dests.metrics.Close(); err != nil {
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

// Acquire a reference on a destination.
//
// Allocates a new ID if no reference exists yet.
func (dests *destinations) Acquire(dest *Destination) (destinationID, error) {
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

	id := destinationID(0)
	if len(ids) > 0 {
		sort.Slice(ids, func(i, j int) bool {
			return ids[i] < ids[j]
		})

		for _, allocatedID := range ids {
			if id < allocatedID {
				break
			}

			id = allocatedID + 1
			if id == 0 || id >= dests.maxID {
				return nil, fmt.Errorf("allocate destination: ran out of ids")
			}
		}
	}

	// Reset metrics to zero. There is currently no more straighforward way to
	// do this.
	var perCPUMetrics []DestinationMetrics
	if err := dests.metrics.Lookup(id, &perCPUMetrics); err != nil {
		return nil, fmt.Errorf("lookup metrics for id %d: %s", id, err)
	}

	zero := make([]DestinationMetrics, len(perCPUMetrics))
	if err := dests.metrics.Put(id, zero); err != nil {
		return nil, fmt.Errorf("zero metrics for id %d: %s", id, err)
	}

	alloc = &destinationAlloc{ID: id}

	// This may replace an unused-but-not-deleted allocation.
	if err := dests.allocs.Update(key, alloc, ebpf.UpdateAny); err != nil {
		return nil, fmt.Errorf("allocate destination: %s", err)
	}

	return alloc, nil
}

// ReleaseByID releases a reference on a destination by its ID.
//
// This function is linear to the number of destinations and should be avoided
// if possible.
func (dests *destinations) ReleaseByID(id destinationID) error {
	var (
		key   destinationKey
		alloc destinationAlloc
		iter  = dests.allocs.Iterate()
	)
	for iter.Next(&key, &alloc) {
		if alloc.ID != id {
			continue
		}

		return dests.releaseAllocation(&key, alloc)
	}
	if err := iter.Err(); err != nil {
		return err
	}
	return fmt.Errorf("release reference: no allocation for id %d", id)
}

// Release a reference on a destination.
func (dests *destinations) Release(dest *Destination) error {
	key, err := newDestinationKey(dest)
	if err != nil {
		return err
	}

	var alloc destinationAlloc
	err = dests.allocs.Lookup(key, &alloc)
	if err != nil {
		return fmt.Errorf("release id for %s: %s", key, err)
	}

	return dests.releaseAllocation(key, alloc)
}

func (dests *destinations) releaseAllocation(key *destinationKey, alloc destinationAlloc) error {
	if alloc.Count == 0 {
		return fmt.Errorf("release id: underflow")
	}

	alloc.Count--
	if dests.allocationInUse(&alloc) {
		if err := dests.allocs.Update(key, &alloc, ebpf.UpdateExist); err != nil {
			return fmt.Errorf("release id for %s: %s", key, err)
		}
		return nil
	}

	// There are no more references, and no socket. We can release the allocation.
	if err := dests.allocs.Delete(key); err != nil {
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

func (dests *destinations) Metrics() (map[Destination]DestinationMetrics, error) {
	list, err := dests.List()
	if err != nil {
		return nil, fmt.Errorf("list destinations: %s", err)
	}

	metrics := make(map[Destination]DestinationMetrics)
	for id, dest := range list {
		var perCPUMetrics []DestinationMetrics
		if err := dests.metrics.Lookup(id, &perCPUMetrics); err != nil {
			return nil, fmt.Errorf("metrics for destination %s: %s", dest, err)
		}

		metrics[*dest] = sumDestinationMetrics(perCPUMetrics)
	}

	return metrics, nil
}

type DestinationMetrics struct {
	// Total number of packets sent to this destination.
	ReceivedPackets uint64
	// Total number of packets dropped due to no socket being available.
	DroppedPacketsMissingSocket uint64
	// Total number of packets dropped due to the socket being incompatible
	// with the incoming traffic.
	DroppedPacketsIncompatibleSocket uint64
}

func sumDestinationMetrics(in []DestinationMetrics) DestinationMetrics {
	if len(in) == 0 {
		return DestinationMetrics{}
	}

	sum := in[0]
	for _, metrics := range in[1:] {
		sum.ReceivedPackets += metrics.ReceivedPackets
		sum.DroppedPacketsMissingSocket += metrics.DroppedPacketsMissingSocket
		sum.DroppedPacketsIncompatibleSocket += metrics.DroppedPacketsIncompatibleSocket
	}

	return sum
}
