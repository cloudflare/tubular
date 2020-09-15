package testutil

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"golang.org/x/sys/unix"
)

// NewNetNS creates a pristine network namespace.
func NewNetNS(tb testing.TB) ns.NetNS {
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

		ip := exec.Command("ip", "link", "set", "dev", "lo", "up")
		if out, err := ip.CombinedOutput(); err != nil {
			if len(out) > 0 {
				tb.Log(string(out))
			}
			errs <- fmt.Errorf("set up loopback: %s", err)
			return
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

// ListenNetNS listens on a given address in a specific network namespace.
//
// Connections are accepted / packets read until
// the test ends.
func ListenNetNS(tb testing.TB, netns ns.NetNS, network, address string) {
	JoinNetNS(tb, netns, func() {
		switch network {
		case "tcp", "tcp4", "tcp6":
			ln, err := net.Listen(network, address)
			if err != nil {
				tb.Fatal("Can't listen:", err)
			}

			tb.Cleanup(func() {
				ln.Close()
			})

			go func() {
				for {
					conn, err := ln.Accept()
					if err != nil {
						if !isErrNetClosing(err) {
							tb.Error("Can't accept:", err)
						}
						return
					}

					go func() {
						_, err := io.Copy(ioutil.Discard, conn)
						if err != nil {
							tb.Error()
						}
						conn.Close()
					}()
				}
			}()

		case "udp", "udp4", "udp6":
			conn, err := net.ListenPacket(network, address)
			if err != nil {
				tb.Fatal("Can't listen:", err)
			}

			tb.Cleanup(func() {
				conn.Close()
			})

			go func() {
				for {
					var buf [1]byte
					_, from, err := conn.ReadFrom(buf[:])
					if err != nil {
						if !isErrNetClosing(err) {
							tb.Error("Can't read UDP packets:", err)
						}
						return
					}
					conn.WriteTo([]byte("b"), from)
				}
			}()

		default:
			tb.Fatal("Unsupported network:", network)
		}
	})
}

// Check if error is net.ErrNetClosing.
//
// Until net.ErrNetClosing gets exported (Go 1.16), match on the error message
// which is guaranteed to stay consistent.
//
// See https://github.com/golang/go/issues/4373
func isErrNetClosing(err error) bool {
	return strings.Contains(err.Error(), "use of closed network connection")
}

// CanDialNetNS returns true if an address can be dialled in a specific network namespace.
func CanDialNetNS(tb testing.TB, netns ns.NetNS, network, address string) (ok bool) {
	dialer := net.Dialer{
		Timeout: 100 * time.Millisecond,
	}

	JoinNetNS(tb, netns, func() {
		switch network {
		case "tcp", "tcp4", "tcp6":
			conn, err := dialer.Dial(network, address)
			if err == nil {
				conn.Close()
				ok = true
				return
			}
			if !errors.Is(err, unix.ECONNREFUSED) {
				tb.Fatal("Can't dial:", err)
			}

		case "udp", "udp4", "udp6":
			conn, err := dialer.Dial(network, address)
			if err != nil {
				tb.Fatal("Can't dial:", err)
			}
			defer conn.Close()

			message := []byte("a")
			_, err = conn.Write(message)
			if err != nil {
				tb.Fatal("Can't write:", err)
			}

			conn.SetReadDeadline(time.Now().Add(time.Second))

			var buf [1]byte
			_, err = conn.Read(buf[:])
			if errors.Is(err, unix.ECONNREFUSED) {
				ok = false
				return
			}
			if err != nil {
				tb.Fatal("Can't read:", err)
			}

			ok = true

		default:
			tb.Fatal("Unsupported network:", network)
		}
	})
	return
}
