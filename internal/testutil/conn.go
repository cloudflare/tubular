package testutil

import (
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// ConnectSocket connects a UDP socket to localhost.
func ConnectSocket(tb testing.TB, conn syscall.Conn) {
	tb.Helper()

	raw, err := conn.SyscallConn()
	if err != nil {
		tb.Fatal(err)
	}

	err = raw.Control(func(fd uintptr) {
		domain, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_DOMAIN)
		if err != nil {
			tb.Fatal("SO_DOMAIN:", err)
		}

		var sa unix.Sockaddr
		switch domain {
		case unix.AF_INET:
			sa = &unix.SockaddrInet4{
				Port: 1234,
				Addr: [4]byte{127, 0, 0, 1},
			}

		case unix.AF_INET6:
			sa = &unix.SockaddrInet6{
				Port: 1234,
				Addr: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			}

		default:
			tb.Fatal("Unsupported domain:", domain)
		}

		err = unix.Connect(int(fd), sa)
		if err != nil {
			tb.Fatal("Connect:", err)
		}
	})
	if err != nil {
		tb.Fatal("Control:", err)
	}
}
