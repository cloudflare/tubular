package testutil

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"code.cfops.it/sys/tubular/internal/utils"
	"github.com/containernetworking/plugins/pkg/ns"
	"golang.org/x/sys/unix"
)

// NewNetNS creates a pristine network namespace.
func NewNetNS(tb testing.TB, networks ...string) ns.NetNS {
	tb.Helper()

	quit := make(chan struct{})
	result := make(chan ns.NetNS, 1)
	errs := make(chan error, 1)
	go func() {
		// We never unlock the OS thread, which has the effect
		// of terminating the thread after the current goroutine
		// exits. This is desirable to avoid other goroutines
		// executing in the wrong namespace.
		runtime.LockOSThread()

		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			errs <- fmt.Errorf("unshare: %s", err)
			return
		}

		ip := exec.Command("/sbin/ip", "link", "set", "dev", "lo", "up")
		if out, err := ip.CombinedOutput(); err != nil {
			if len(out) > 0 {
				tb.Log(string(out))
			}
			errs <- fmt.Errorf("set up loopback: %s", err)
			return
		}

		for _, network := range networks {
			ip := exec.Command("/sbin/ip", "addr", "add", "dev", "lo", network)
			if out, err := ip.CombinedOutput(); err != nil {
				if len(out) > 0 {
					tb.Log(string(out))
				}
				errs <- fmt.Errorf("add networks: %s", err)
				return
			}
		}

		netns, err := ns.GetCurrentNS()
		if err != nil {
			errs <- fmt.Errorf("get current network namespace: %s", err)
			return
		}

		result <- netns

		// Block the goroutine (and the thread) until the
		// network namespace isn't needed anymore.
		<-quit
	}()

	select {
	case err := <-errs:
		tb.Fatal(err)
		return nil

	case netns := <-result:
		tb.Cleanup(func() {
			close(quit)
			netns.Close()
		})

		return netns
	}
}

// JoinNetNS executes a function in a different network namespace.
//
// Any goroutines invoked from the function will still execute in the
// parent network namespace.
func JoinNetNS(tb testing.TB, netns ns.NetNS, fn func()) {
	tb.Helper()

	current, err := ns.GetCurrentNS()
	if err != nil {
		tb.Fatal(err)
	}
	defer current.Close()

	runtime.LockOSThread()

	if err := netns.Set(); err != nil {
		tb.Fatal("Can't join namespace:", err)
	}

	defer func() {
		if err := current.Set(); err != nil {
			tb.Fatal("Can't switch to original namespace:", err)
		}
		runtime.UnlockOSThread()
	}()

	fn()
}

// ListenAndEcho calls Listen and then starts an echo server on the returned connection.
func ListenAndEcho(tb testing.TB, netns ns.NetNS, network, address string) (sys syscall.Conn) {
	return ListenAndEchoWithName(tb, netns, network, address, "default")
}

const maxNameLen = 128

// Listen listens on a given address in a specific network namespace.
//
// Uses a local address if address is empty.
func Listen(tb testing.TB, netns ns.NetNS, network, address string) (sys syscall.Conn) {
	if address == "" {
		switch network {
		case "tcp", "tcp4", "udp", "udp4":
			address = "127.0.0.1:0"
		case "tcp6", "udp6":
			address = "[::1]:0"
		case "unix", "unixpacket", "unixgram":
			address = filepath.Join(tb.TempDir(), "sock")
		default:
			tb.Fatal("Don't know how to make address for", network)
		}
	}
	JoinNetNS(tb, netns, func() {
		switch network {
		case "tcp", "tcp4", "tcp6", "unix", "unixpacket":
			ln, err := net.Listen(network, address)
			if err != nil {
				tb.Fatal("Can't listen:", err)
			}
			sys = ln.(syscall.Conn)

			tb.Cleanup(func() {
				ln.Close()
			})

		case "udp", "udp4", "udp6", "unixgram":
			conn, err := net.ListenPacket(network, address)
			if err != nil {
				tb.Fatal("Can't listen:", err)
			}
			sys = conn.(syscall.Conn)

			tb.Cleanup(func() {
				conn.Close()
			})

		default:
			tb.Fatal("Unsupported network:", network)
		}
	})

	return
}

// ListenAndEchoWithName is like ListenAndEcho, except that you can distinguish
// multiple listeners by using CanDialName.
func ListenAndEchoWithName(tb testing.TB, netns ns.NetNS, network, address, name string) (sys syscall.Conn) {
	if len(name) > maxNameLen {
		tb.Fatalf("name exceeds %d bytes", maxNameLen)
	}

	sys = Listen(tb, netns, network, address)
	go echo(tb, network, sys, name)
	return
}

func echo(tb testing.TB, network string, sys syscall.Conn, name string) {
	switch network {
	case "tcp", "tcp4", "tcp6", "unix", "unixpacket":
		ln := sys.(net.Listener)
		for {
			conn, err := ln.Accept()
			if err != nil {
				if !utils.IsErrNetClosed(err) {
					tb.Error("Can't accept:", err)
				}
				return
			}

			go func() {
				defer conn.Close()

				conn.SetWriteDeadline(time.Now().Add(time.Second))
				_, err := conn.Write([]byte(name))
				if err != nil {
					tb.Error(err)
					return
				}

				_, err = io.Copy(ioutil.Discard, conn)
				if err != nil {
					tb.Error(err)
				}
			}()
		}

	case "udp", "udp4", "udp6", "unixgram":
		conn := sys.(net.PacketConn)
		for {
			var buf [1]byte
			_, from, err := conn.ReadFrom(buf[:])
			if err != nil {
				if !utils.IsErrNetClosed(err) {
					tb.Error("Can't read UDP packets:", err)
				}
				return
			}

			conn.WriteTo([]byte(name), from)
		}

	default:
		tb.Fatal("Unsupported network:", network)
	}
}

// CanDial returns true if an address can be dialled in a specific network namespace.
func CanDial(tb testing.TB, netns ns.NetNS, network, address string) (ok bool) {
	tb.Helper()

	JoinNetNS(tb, netns, func() {
		tb.Helper()

		_, conn := dial(tb, network, address)
		if conn != nil {
			ok = true
			conn.(io.Closer).Close()
		}
	})

	return
}

// CanDialName checks that a ListenWithName is reachable at the given network and address.
func CanDialName(tb testing.TB, netns ns.NetNS, network, address, name string) {
	tb.Helper()

	var (
		conn     syscall.Conn
		haveName string
	)
	JoinNetNS(tb, netns, func() {
		tb.Helper()

		haveName, conn = dial(tb, network, address)
	})
	if conn == nil {
		tb.Fatal("Can't dial", network, address)
	}
	conn.(io.Closer).Close()

	if haveName != name {
		tb.Fatalf("Expected to reach %q at %s %s, got %q instead", name, network, address, haveName)
	}
}

// Dial connects to network and address in the given network namespace.
func Dial(tb testing.TB, netns ns.NetNS, network, address string) (conn syscall.Conn) {
	tb.Helper()

	JoinNetNS(tb, netns, func() {
		tb.Helper()

		_, conn = dial(tb, network, address)
		if conn == nil {
			tb.Fatal("Can't dial", network, address)
		}
	})

	return
}

func dial(tb testing.TB, network, address string) (string, syscall.Conn) {
	tb.Helper()

	dialer := net.Dialer{
		Timeout: 100 * time.Millisecond,
	}

	switch network {
	case "tcp", "tcp4", "tcp6":
		conn, err := dialer.Dial(network, address)
		if errors.Is(err, unix.ECONNREFUSED) {
			return "", nil
		}
		if err != nil {
			tb.Fatal("Can't dial:", err)
		}
		tb.Cleanup(func() { conn.Close() })

		buf := make([]byte, maxNameLen)
		n, err := conn.Read(buf)
		if err != nil {
			conn.Close()
			tb.Fatal("Can't read name:", err)
		}

		return string(buf[:n]), conn.(syscall.Conn)

	case "udp", "udp4", "udp6":
		conn, err := dialer.Dial(network, address)
		if err != nil {
			tb.Fatal("Can't dial:", err)
		}
		tb.Cleanup(func() { conn.Close() })

		message := []byte("a")
		_, err = conn.Write(message)
		if err != nil {
			tb.Fatal("Can't write:", err)
		}

		conn.SetReadDeadline(time.Now().Add(time.Second))

		buf := make([]byte, maxNameLen)
		n, err := conn.Read(buf)
		if errors.Is(err, unix.ECONNREFUSED) {
			conn.Close()
			return "", nil
		}
		if err != nil {
			tb.Fatal("Can't read:", err)
		}

		return string(buf[:n]), conn.(syscall.Conn)

	default:
		panic("unsupported network: " + network)
	}
}
