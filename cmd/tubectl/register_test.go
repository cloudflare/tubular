package main

import (
	"errors"
	"io/ioutil"
	"net"
	"os"
	"syscall"
	"testing"

	"code.cfops.it/sys/tubular/internal"
	"code.cfops.it/sys/tubular/internal/sysconn"
	"code.cfops.it/sys/tubular/internal/testutil"

	"github.com/containernetworking/plugins/pkg/ns"
	"golang.org/x/sys/unix"
)

func TestSingleRegisterCommand(t *testing.T) {
	netns := testutil.NewNetNS(t)

	run := func(t *testing.T, args []string, env testEnv, fds testFds) error {
		mustLoadDispatcher(t, netns)

		tubectl := tubectlTestCall{
			NetNS:    netns,
			ExecNS:   netns,
			Cmd:      "register",
			Args:     args,
			Env:      env,
			ExtraFds: fds,
		}
		_, err := tubectl.Run(t)

		return err
	}

	check := func(t *testing.T, dp *internal.Dispatcher, fds testFds) {
		dests := destinations(t, dp)
		if len(dests) != len(fds) {
			t.Fatalf("expected %v registered destination(s), have %v", len(fds), len(dests))
		}

		for _, f := range fds {
			cookie := mustSocketCookie(t, f)
			if _, ok := dests[cookie]; !ok {
				t.Fatalf("expected registered destination for socket %v", cookie)
			}
		}
	}

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
			err := run(t, tc.cmdArgs, tc.extraEnv, tc.extraFds)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("unexpected error: want %v, have %v", tc.wantErr, err)
			}

			dp := mustOpenDispatcher(t, netns)
			if tc.wantErr != nil {
				check(t, dp, nil)
			} else {
				check(t, dp, tc.extraFds)
			}
		})
	}

	for _, network := range []string{"udp4", "udp6", "tcp4", "tcp6"} {
		t.Run("reuseport "+network, func(t *testing.T) {
			fds := testFds(testutil.ReuseportGroup(t, netns, network, 3))
			err := run(t, []string{"svc-label"}, testEnv{"LISTEN_FDS": "3"}, fds)
			if err != nil {
				t.Fatal("Unexpected error:", err)
			}

			dp := mustOpenDispatcher(t, netns)
			check(t, dp, testFds{fds[0]})
		})

		t.Run("multiple sockets rejected "+network, func(t *testing.T) {
			fds := testFds{
				testutil.Listen(t, netns, network, ""),
				testutil.Listen(t, netns, network, ""),
			}
			err := run(t, []string{"svc-label"}, testEnv{"LISTEN_FDS": "2"}, fds)
			if err == nil {
				t.Fatal("Expected an error")
			}

			// We still register the first fd even if there is an error.
			dp := mustOpenDispatcher(t, netns)
			check(t, dp, testFds{fds[1]})
		})
	}
}

func destinations(tb testing.TB, dp *internal.Dispatcher) map[internal.SocketCookie]internal.Destination {
	tb.Helper()

	_, cookies, err := dp.Destinations()
	if err != nil {
		tb.Fatalf("dispatcher destinations: %s", err)
	}

	destsByCookie := make(map[internal.SocketCookie]internal.Destination)
	for dest, cookie := range cookies {
		destsByCookie[cookie] = dest
	}
	return destsByCookie
}

func mustSocketCookie(tb testing.TB, conn syscall.Conn) internal.SocketCookie {
	tb.Helper()

	cookie, err := socketCookie(conn)
	if err != nil {
		tb.Fatal(err)
	}

	return cookie
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
	v6only, err := sysconn.ControlInt(ln, func(fd int) (int, error) {
		return unix.GetsockoptInt(fd, syscall.SOL_IPV6, syscall.IPV6_V6ONLY)
	})
	if err != nil {
		tb.Fatal(err)
	}
	if v6only != 0 {
		tb.Fatal("socket is in V6ONLY mode")
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

func TestSequenceRegisterDifferentSocket(t *testing.T) {
	netns := mustReadyNetNS(t)

	for i := 0; i < 2; i++ {
		sk := testutil.Listen(t, netns, "tcp4", "")

		tubectl := tubectlTestCall{
			NetNS:    netns,
			ExecNS:   netns,
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

func TestRegisterRefuseDifferentNamespace(t *testing.T) {
	netns := mustReadyNetNS(t)
	sk := testutil.Listen(t, netns, "tcp4", "")

	tubectl := tubectlTestCall{
		NetNS: netns,
		// ExecNS is not set
		Cmd:      "register",
		Args:     []string{"my-service"},
		Env:      testEnv{"LISTEN_FDS": "1"},
		ExtraFds: testFds{sk},
	}
	if _, err := tubectl.Run(t); err == nil {
		t.Error("Didn't refuse a socket from a different namespace")
	}
}
