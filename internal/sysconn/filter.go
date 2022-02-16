package sysconn

import (
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
	"inet.af/netaddr"
)

// Predicate is a condition for keeping or rejecting a file.
type Predicate func(fd int) (keep bool, err error)

// FilterFD is like FilterConn except that it takes a raw fd.
func FilterFd(fd int, ps ...Predicate) (keep bool, err error) {
	for _, p := range ps {
		keep, err = p(fd)
		if err != nil || !keep {
			return
		}
	}
	return
}

// Apply a list of predicates to a conn.
//
// Returns true if all predicates return true, false if no predicates were
// given.
func FilterConn(conn syscall.Conn, ps ...Predicate) (keep bool, err error) {
	err = Control(conn, func(fd int) (err error) {
		keep, err = FilterFd(fd, ps...)
		return
	})
	return
}

// Filter a list of conns with a list of predicates.
//
// Returns a list of conns for which all predicates returned true.
func Filter(conns []syscall.Conn, ps ...Predicate) ([]syscall.Conn, error) {
	var result []syscall.Conn
	for _, conn := range conns {
		keep, err := FilterConn(conn, ps...)
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
// Non-reuseport sockets and non-sockets are ignored.
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

// IgnoreENOTSOCK wraps a predicate and returns false instead of unix.ENOTSOCK.
func IgnoreENOTSOCK(p Predicate) Predicate {
	return func(fd int) (bool, error) {
		keep, err := p(fd)
		if errors.Is(err, unix.ENOTSOCK) {
			return false, nil
		}
		return keep, err
	}
}

// InetListener returns a predicate that keeps listening TCP or connected UDP sockets.
//
// It filters out any files that are not sockets.
func InetListener(network string) Predicate {
	return func(fd int) (bool, error) {
		domain, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
		if err != nil {
			return false, err
		}
		if domain != unix.AF_INET && domain != unix.AF_INET6 {
			return false, nil
		}

		soType, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
		if err != nil {
			return false, fmt.Errorf("getsockopt(SO_TYPE): %s", err)
		}

		switch network {
		case "udp":
			if soType != unix.SOCK_DGRAM {
				return false, nil
			}

		case "tcp":
			if soType != unix.SOCK_STREAM {
				return false, nil
			}

		default:
			return false, fmt.Errorf("unrecognized network %q", network)
		}

		switch soType {
		case unix.SOCK_STREAM:
			acceptConn, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
			if err != nil {
				return false, fmt.Errorf("getsockopt(SO_ACCEPTCONN): %s", err)
			}

			if acceptConn == 0 {
				// Not a listening socket
				return false, nil
			}

		case unix.SOCK_DGRAM:
			sa, err := unix.Getpeername(fd)
			if err != nil && !errors.Is(err, unix.ENOTCONN) {
				return false, fmt.Errorf("getpeername: %s", err)
			}

			if sa != nil {
				// Not a connected socket
				return false, nil
			}

		default:
			return false, nil
		}

		return true, nil
	}
}

// LocalAddress filters for sockets with the given address and port.
func LocalAddress(ip netaddr.IP, port int) Predicate {
	return func(fd int) (bool, error) {
		sa, err := unix.Getsockname(fd)
		if err != nil {
			return false, fmt.Errorf("getsockname: %s", err)
		}

		var fdIP netaddr.IP
		var fdPort int
		switch addr := sa.(type) {
		case *unix.SockaddrInet4:
			fdIP, _ = netaddr.FromStdIP(addr.Addr[:])
			fdPort = addr.Port

		case *unix.SockaddrInet6:
			fdIP = netaddr.IPv6Raw(addr.Addr)
			fdPort = addr.Port

		default:
			return false, nil
		}

		if fdIP.Compare(ip) != 0 {
			return false, nil
		}

		if fdPort != port {
			return false, nil
		}

		return true, nil
	}
}
