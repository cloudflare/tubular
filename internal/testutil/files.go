package testutil

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
	"time"

	"code.cfops.it/sys/tubular/pkg/sysconn"

	"golang.org/x/sys/unix"
)

// FileStatusFlags returns flags for the open file description onderlying conn.
func FileStatusFlags(tb testing.TB, conn syscall.Conn) int {
	tb.Helper()

	flags, err := sysconn.ControlInt(conn, func(fd int) (int, error) {
		return unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	})
	if err != nil {
		tb.Fatal("fcntl(F_GETFL):", err)
	}

	return flags
}

// OpenFiles returns the specified number of files.
//
// The files are a random mixture of pipes, TCP and UDP sockets.
func OpenFiles(tb testing.TB, n int) []*os.File {
	tb.Helper()

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	var files []*os.File
	tb.Cleanup(func() {
		for _, file := range files {
			file.Close()
		}
	})

	for i := 0; i < n; i++ {
		var filer interface {
			File() (*os.File, error)
			Close() error
		}

		switch rng.Intn(3) {
		case 0:
			a, b, err := os.Pipe()
			if err != nil {
				tb.Fatal("Pipe:", err)
			}
			b.Close()
			files = append(files, a)
			continue

		case 1:
			ln, err := net.Dial("udp4", "127.0.0.1:0")
			if err != nil {
				tb.Fatal("Dial:", err)
			}
			filer = ln.(*net.UDPConn)

		case 2:
			ln, err := net.Listen("tcp6", "[::1]:0")
			if err != nil {
				tb.Fatal("Listen:", err)
			}
			filer = ln.(*net.TCPListener)
		}

		file, err := filer.File()
		if err != nil {
			filer.Close()
			tb.Fatal("File:", err)
		}
		filer.Close()

		files = append(files, file)
	}

	return files
}

// ReuseportSockets creates two sockets that listen on the same port on either
// 127.0.0.1 or ::1, depending on the network.
func ReuseportSockets(tb testing.TB, network string) (a, b *os.File, ip net.IP, port int) {
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

	type filer interface {
		File() (*os.File, error)
		Close() error
	}

	file := func(filer filer) *os.File {
		file, err := filer.File()
		if err != nil {
			tb.Fatalf("%T.File: %s", filer, err)
		}
		tb.Cleanup(func() { file.Close() })
		return file
	}

	var fn func(string) (*os.File, int)
	switch network {
	case "tcp4", "tcp6":
		fn = func(addr string) (*os.File, int) {
			conn, err := lc.Listen(context.Background(), network, addr)
			if err != nil {
				tb.Fatal("Listen:", err)
			}
			defer conn.Close()
			return file(conn.(filer)), conn.Addr().(*net.TCPAddr).Port
		}

	case "udp4", "udp6":
		fn = func(addr string) (*os.File, int) {
			conn, err := lc.ListenPacket(context.Background(), network, addr)
			if err != nil {
				tb.Fatal("Listen:", err)
			}
			defer conn.Close()

			tb.Cleanup(func() { conn.Close() })
			return file(conn.(filer)), conn.LocalAddr().(*net.UDPAddr).Port
		}

	default:
		tb.Fatal("unsupported network", network)
	}

	switch network {
	case "tcp4", "udp4":
		ip = net.IPv4(127, 0, 0, 1)
		a, port = fn("127.0.0.1:0")
		b, _ = fn("127.0.0.1:" + fmt.Sprint(port))
	case "tcp6", "udp6":
		ip = net.ParseIP("::1")
		a, port = fn("[::1]:0")
		b, _ = fn("[::1]:" + fmt.Sprint(port))
	}

	return
}

// SpawnChildWithFiles creates a process that holds onto a bunch of files.
func SpawnChildWithFiles(tb testing.TB, files ...*os.File) (pid int) {
	tb.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		tb.Fatal("Pipe:", err)
	}
	defer r.Close()
	tb.Cleanup(func() { w.Close() })

	out, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		tb.Fatal(err)
	}
	defer out.Close()

	// Make stdin, stdout, stderr blocking
	_ = r.Fd()
	_ = out.Fd()

	fds := []uintptr{sysConnFd(tb, r), sysConnFd(tb, out), sysConnFd(tb, out)}
	for _, file := range files {
		fds = append(fds, sysConnFd(tb, file))
	}

	catPath, err := exec.LookPath("cat")
	if err != nil {
		tb.Fatal(err)
	}

	pid, _, err = syscall.StartProcess(catPath, []string{catPath}, &syscall.ProcAttr{
		Files: fds,
	})
	if err != nil {
		tb.Fatal(err)
	}

	runtime.KeepAlive(files)

	child, _ := os.FindProcess(pid)
	// Reap child as quickly as possible to make pidfd calls fail if the
	// process exits.
	go func() { child.Wait() }()
	tb.Cleanup(func() { child.Kill() })

	// Wait until cat reads from the stdin pipe, which signals that start up
	// like the dynamic loader is done.
	w.Write([]byte{'a'})

	return
}

func sysConnFd(tb testing.TB, conn syscall.Conn) (ret uintptr) {
	tb.Helper()

	raw, err := conn.SyscallConn()
	if err != nil {
		tb.Fatal(err)
	}

	err = raw.Control(func(fd uintptr) {
		ret = fd
	})
	if err != nil {
		tb.Fatal(err)
	}
	return
}
