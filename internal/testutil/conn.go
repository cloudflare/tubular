package testutil

import (
	"context"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"

	"github.com/cloudflare/tubular/internal/sysconn"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/containernetworking/plugins/pkg/ns"
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

func DropIncomingTraffic(tb testing.TB, conn syscall.Conn) {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SocketFilter,
		Instructions: asm.Instructions{
			// Truncate the packet to zero bytes.
			asm.Mov.Imm32(asm.R0, 0),
			asm.Return(),
		},
		License: "Proprietary",
	})
	if err != nil {
		tb.Fatal(err)
	}
	defer prog.Close()

	err = sysconn.Control(conn, func(fd int) error {
		return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, prog.FD())
	})
	if err != nil {
		tb.Fatal(err)
	}
}

// ReuseportGroup creates sockets that listen on the same port on either
// 127.0.0.1 or ::1, depending on the network.
func ReuseportGroup(tb testing.TB, netns ns.NetNS, network string, n int) (conns []syscall.Conn) {
	tb.Cleanup(func() {
		for _, conn := range conns {
			conn.(io.Closer).Close()
		}
	})

	lc := &net.ListenConfig{
		Control: func(network, address string, raw syscall.RawConn) error {
			err := raw.Control(func(fd uintptr) {
				err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
				if err != nil {
					tb.Fatal("setsockopt(SO_REUSEPORT):", err)
				}
			})
			return err
		},
	}

	var fn func(string) (syscall.Conn, int, error)
	switch network {
	case "tcp4", "tcp6":
		fn = func(addr string) (syscall.Conn, int, error) {
			conn, err := lc.Listen(context.Background(), network, addr)
			if err != nil {
				return nil, 0, err
			}
			return conn.(syscall.Conn), conn.Addr().(*net.TCPAddr).Port, nil
		}

	case "udp4", "udp6":
		fn = func(addr string) (syscall.Conn, int, error) {
			conn, err := lc.ListenPacket(context.Background(), network, addr)
			if err != nil {
				return nil, 0, err
			}
			return conn.(syscall.Conn), conn.LocalAddr().(*net.UDPAddr).Port, nil
		}

	default:
		tb.Fatal("unsupported network", network)
	}

	var addr string
	switch network {
	case "tcp4", "udp4":
		addr = "127.0.0.1"
	case "tcp6", "udp6":
		addr = "[::1]"
	}

	JoinNetNS(tb, netns, func() error {
		conn, port, err := fn(addr + ":0")
		if err != nil {
			return err
		}
		conns = []syscall.Conn{conn}
		for i := 1; i < n; i++ {
			conn, _, err = fn(fmt.Sprintf("%s:%d", addr, port))
			if err != nil {
				return err
			}
			conns = append(conns, conn)
		}
		return nil
	})

	return
}
