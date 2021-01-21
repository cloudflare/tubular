package main

import (
	"errors"
	"io/ioutil"
	"net"
	"os"
	"syscall"
	"testing"

	"code.cfops.it/sys/tubular/internal"
	"code.cfops.it/sys/tubular/internal/testutil"

	"github.com/containernetworking/plugins/pkg/ns"
	"golang.org/x/sys/unix"
)

func TestSingleRegisterCommand(t *testing.T) {
	netns := testutil.NewNetNS(t)

	for _, tc := range []struct {
		name     string
		wantErr  error
		cmdArgs  []string
		extraEnv testEnv
		extraFds testFds
	}{
		{"label missing", errBadArg,
			nil, nil, nil},
		{"label empty", errBadArg,
			[]string{""}, nil, nil},
		{"listen_fds empty", errBadArg,
			[]string{"svc-label"}, testEnv{"LISTEN_FDS": ""}, nil},
		{"listen_fds zero", errBadArg,
			[]string{"svc-label"}, testEnv{"LISTEN_FDS": "0"}, nil},
		{"listen_fds two", errBadArg,
			[]string{"svc-label"}, testEnv{"LISTEN_FDS": "2"}, nil},
		{"fd unused", errBadFD,
			[]string{"svc-label"}, testEnv{"LISTEN_FDS": "1"}, testFds{nil}},
		{"fd non-socket", internal.ErrNotSocket,
			[]string{"svc-label"}, testEnv{"LISTEN_FDS": "1"}, testFds{makeNonSocket(t)}},
		{"fd dual-stack socket", internal.ErrBadSocketState,
			[]string{"svc-label"}, testEnv{"LISTEN_FDS": "1"}, testFds{makeDualStackSocket(t, netns)}},
		{"fd unix socket", internal.ErrBadSocketDomain,
			[]string{"svc-label"}, testEnv{"LISTEN_FDS": "1"}, testFds{makeListeningSocket(t, netns, "unix")}},
		{"fd unixpacket socket", internal.ErrBadSocketDomain,
			[]string{"svc-label"}, testEnv{"LISTEN_FDS": "1"}, testFds{makeListeningSocket(t, netns, "unixpacket")}},
		{"fd unixgram socket", internal.ErrBadSocketDomain,
			[]string{"svc-label"}, testEnv{"LISTEN_FDS": "1"}, testFds{makeListeningSocket(t, netns, "unixgram")}},
		{"fd connected tcp4", internal.ErrBadSocketState,
			[]string{"svc-label"}, testEnv{"LISTEN_FDS": "1"}, testFds{makeConnectedSocket(t, netns, "tcp4")}},
		{"fd connected tcp6", internal.ErrBadSocketState,
			[]string{"svc-label"}, testEnv{"LISTEN_FDS": "1"}, testFds{makeConnectedSocket(t, netns, "tcp6")}},
		{"fd connected udp4", internal.ErrBadSocketState,
			[]string{"svc-label"}, testEnv{"LISTEN_FDS": "1"}, testFds{makeConnectedSocket(t, netns, "udp4")}},
		{"fd connected udp6", internal.ErrBadSocketState,
			[]string{"svc-label"}, testEnv{"LISTEN_FDS": "1"}, testFds{makeConnectedSocket(t, netns, "udp6")}},
		{"fd listening tcp4", nil,
			[]string{"svc-label"}, testEnv{"LISTEN_FDS": "1"}, testFds{makeListeningSocket(t, netns, "tcp4")}},
		{"fd listening tcp6", nil,
			[]string{"svc-label"}, testEnv{"LISTEN_FDS": "1"}, testFds{makeListeningSocket(t, netns, "tcp6")}},
		{"fd listening udp4", nil,
			[]string{"svc-label"}, testEnv{"LISTEN_FDS": "1"}, testFds{makeListeningSocket(t, netns, "udp4")}},
		{"fd listening udp6", nil,
			[]string{"svc-label"}, testEnv{"LISTEN_FDS": "1"}, testFds{makeListeningSocket(t, netns, "udp6")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mustLoadDispatcher(t, netns)

			flags := make(map[syscall.Conn]int)
			for _, f := range tc.extraFds {
				if f != nil {
					flags[f] = testutil.FileStatusFlags(t, f)
				}
			}

			tubectl := tubectlTestCall{
				NetNS:    netns,
				Cmd:      "register",
				Args:     tc.cmdArgs,
				Env:      tc.extraEnv,
				ExtraFds: tc.extraFds,
			}
			_, err := tubectl.Run(t)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("unexpected error: want %v, have %v", tc.wantErr, err)
			}

			dests := destinations(t, netns)
			if tc.wantErr != nil {
				if len(dests) != 0 {
					t.Fatalf("expected no registered destinations, have %v", len(dests))
				}
				return
			}

			if len(dests) != len(tc.extraFds) {
				t.Fatalf("expected %v registered destination(s), have %v", len(tc.extraFds), len(dests))
			}

			for _, f := range tc.extraFds {
				cookie := socketCookie(t, f)
				if _, ok := dests[cookie]; !ok {
					t.Fatalf("expected registered destination for socket %v", cookie)
				}

				if have := testutil.FileStatusFlags(t, f); have != flags[f] {
					t.Fatalf("file status flags of %v changed: %d != %d", cookie, have, flags[f])
				}
			}
		})
	}
}

func destinations(tb testing.TB, netns ns.NetNS) map[internal.SocketCookie]internal.Destination {
	tb.Helper()
	dp := mustOpenDispatcher(tb, netns)

	dstVec, err := dp.Destinations()
	if err != nil {
		tb.Fatalf("dispatcher destinations: %s", err)
	}
	dstMap := make(map[internal.SocketCookie]internal.Destination, len(dstVec))
	for _, d := range dstVec {
		dstMap[d.Socket] = d
	}
	return dstMap
}

func socketCookie(tb testing.TB, conn syscall.Conn) internal.SocketCookie {
	tb.Helper()

	raw, err := conn.SyscallConn()
	if err != nil {
		tb.Fatalf("SyscallConn: %v", err)
	}

	var (
		cookie uint64
		opErr  error
	)
	err = raw.Control(func(fd uintptr) {
		cookie, opErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
	})
	if err != nil {
		tb.Fatalf("RawConn.Control: %v", err)
	}
	if opErr != nil {
		tb.Fatalf("Getsockopt(SO_COOKIE): %v", err)
	}

	return internal.SocketCookie(cookie)
}

func makeNonSocket(tb testing.TB) syscall.Conn {
	tb.Helper()

	tmpFile, err := ioutil.TempFile("", "non_socket_")
	if err != nil {
		tb.Fatal("can't create temporary file:", err)
	}
	os.Remove(tmpFile.Name())
	tb.Cleanup(func() { tmpFile.Close() })

	return tmpFile
}

func makeDualStackSocket(tb testing.TB, netns ns.NetNS) syscall.Conn {
	tb.Helper()

	ln := testutil.Listen(tb, netns, "tcp", ":0")
	rc, err := ln.SyscallConn()
	if err != nil {
		tb.Fatal("SyscallConn failed: ", err)
	}
	err = rc.Control(func(fd uintptr) {
		v6only, err := syscall.GetsockoptInt(int(fd), syscall.SOL_IPV6, syscall.IPV6_V6ONLY)
		if err != nil {
			tb.Fatal("Getsockopt failed: ", err)
		}
		if v6only != 0 {
			tb.Fatal("socket is in V6ONLY mode")
		}
	})
	if err != nil {
		tb.Fatal("RawConn.Control failed: ", err)
	}

	return ln
}

func makeListeningSocket(tb testing.TB, netns ns.NetNS, network string) syscall.Conn {
	tb.Helper()

	return testutil.Listen(tb, netns, network, "")
}

func makeConnectedSocket(tb testing.TB, netns ns.NetNS, network string) syscall.Conn {
	tb.Helper()

	var laddr net.Addr
	ln := testutil.ListenAndEcho(tb, netns, network, "")
	switch ln := ln.(type) {
	case *net.TCPListener:
		laddr = ln.Addr()
	case *net.UDPConn:
		laddr = ln.LocalAddr()
	default:
		tb.Fatal("unexpected listener type")
	}

	return testutil.Dial(tb, netns, network, laddr.String())
}

// Tests for simple unregister

func TestUnregisterFailsWithoutLabelOrSocketCookie(t *testing.T) {
}

func TestUnregisterFailsForInvalidLabel(t *testing.T) {
}

func TestUnregisterFailsForInvalidSocketCookie(t *testing.T) {
}

func TestUnregisterValidLabelAndSocketCookie(t *testing.T) {
}

// Tests for sequences of register/unregister

func TestSequenceRegisterDifferentSocket(t *testing.T) {
	netns := mustReadyNetNS(t)

	for i := 0; i < 2; i++ {
		sk := testutil.Listen(t, netns, "tcp4", "")

		tubectl := tubectlTestCall{
			NetNS:    netns,
			Cmd:      "register",
			Args:     []string{"my-service"},
			Env:      testEnv{"LISTEN_FDS": "1"},
			ExtraFds: testFds{sk},
		}
		if _, err := tubectl.Run(t); err != nil {
			t.Fatal("register failed:", err)
		}

		if _, err := testTubectl(t, netns, "list"); err != nil {
			t.Fatal("list failed:", err)
		}

		// TODO: Check registered socket cookie
	}
}

func TestSequenceUnregisterUnregister(t *testing.T) {
}

func TestSequenceRegisterUnregisterReregister(t *testing.T) {
}
