package sysconn

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
	"inet.af/netaddr"
)

// Predicate is a condition for keeping or rejecting a file.
type Predicate func(fd int) (keep bool, err error)

// Apply executes a predicate for a single conn.
func (p Predicate) Apply(conn syscall.Conn) (keep bool, err error) {
	err = Control(conn, func(fd int) (err error) {
		keep, err = p(fd)
		return
	})
	return
}

func Filter(conns []syscall.Conn, p Predicate) ([]syscall.Conn, error) {
	var result []syscall.Conn
	for _, conn := range conns {
		keep, err := p.Apply(conn)
		if err != nil {
			return nil, err
		}
		if keep {
			result = append(result, conn)
		}
	}
	return result, nil
}

// FirstReuseport filters out all but the first socket of a reuseport group.
//
// Non-reuseport sockets are ignored.
func FirstReuseport() Predicate {
	type key struct {
		proto int
		ip    netaddr.IP
		port  uint16
	}

	seen := make(map[key]bool)
	return func(fd int) (bool, error) {
		reuseport, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT)
		if err != nil {
			return false, fmt.Errorf("getsockopt(SO_REUSEPORT): %w", err)
		}
		if reuseport != 1 {
			return true, nil
		}

		proto, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PROTOCOL)
		if err != nil {
			return false, fmt.Errorf("getsockopt(SO_PROTOCOL): %w", err)
		}

		sa, err := unix.Getsockname(fd)
		if err != nil {
			return false, fmt.Errorf("getsockname: %w", err)
		}

		k := key{proto: proto}
		switch addr := sa.(type) {
		case *unix.SockaddrInet4:
			k.ip, _ = netaddr.FromStdIP(addr.Addr[:])
			k.port = uint16(addr.Port)
		case *unix.SockaddrInet6:
			k.ip = netaddr.IPv6Raw(addr.Addr)
			k.port = uint16(addr.Port)
		default:
			return false, fmt.Errorf("unsupported address family: %T", sa)
		}

		if seen[k] {
			return false, nil
		}

		seen[k] = true
		return true, nil
	}
}
