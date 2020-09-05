package internal

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"

	"golang.org/x/net/nettest"

	"code.cfops.it/sys/tubular/internal/testutil"
)

func TestLoadDispatcher(t *testing.T) {
	netns := testutil.NewNetNS(t)

	dp := mustCreateDispatcher(t, netns.Path())
	if err := dp.Close(); err != nil {
		t.Fatal("Can't close dispatcher:", err)
	}

	if _, err := os.Stat(dp.Path); err != nil {
		t.Error("State directory doesn't exist:", err)
	}

	dp = mustOpenDispatcher(t, netns.Path())
	defer dp.Close()

	if err := dp.Unload(); err != nil {
		t.Fatal("Can't unload:", err)
	}

	if _, err := os.Stat(dp.Path); err == nil {
		t.Error("State directory remains after unload")
	}

	// TODO: Check that program is detached
}

func TestDispatcherLocking(t *testing.T) {
	netns := testutil.NewNetNS(t)
	mustCreateDispatcher(t, netns.Path())

	_, err := OpenDispatcher(netns.Path(), "/sys/fs/bpf")
	if err == nil {
		t.Fatal("Dispatcher doesn't lock the state")
	}
}

func TestOverlappingBindings(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, netns.Path())

	bindA := mustNewBinding(t, "foo", TCP, "127.0.0.1/32", 8080)
	if err := dp.AddBinding(bindA); err != nil {
		t.Fatal("can't add /32:", err)
	}

	bindB := mustNewBinding(t, "foo", TCP, "127.0.0.1/24", 8080)
	if err := dp.AddBinding(bindB); err != nil {
		t.Fatal("can't add /24:", err)
	}

	if err := dp.AddBinding(bindB); err == nil {
		t.Error("Bindings can be added multiple times")
	}

	// TODO: Check that connections reach the correct service.
}

func TestAddAndRemoveBindings(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, netns.Path())

	testcases := []struct {
		ip string
		*Binding
	}{
		{"127.0.0.1", mustNewBinding(t, "foo", TCP, "127.0.0.0/8", 8080)},
		{"127.0.0.1", mustNewBinding(t, "foo", UDP, "127.0.0.0/8", 8080)},
		{"[::1]", mustNewBinding(t, "foo", TCP, "::1", 8080)},
		{"[::1]", mustNewBinding(t, "foo", UDP, "::1", 8080)},
	}

	for _, tc := range testcases {
		name := fmt.Sprintf("%v %s", tc.Protocol, tc.Prefix)
		t.Run(name, func(t *testing.T) {
			network := tc.Protocol.String()
			testutil.ListenNetNS(t, netns, network, tc.ip+":8080")

			if !testutil.CanDialNetNS(t, netns, network, tc.ip+":8080") {
				t.Fatal("Can't dial before creating the binding")
			}

			err := dp.AddBinding(tc.Binding)
			if err != nil {
				t.Fatal("Can't create binding:", err)
			}

			if testutil.CanDialNetNS(t, netns, network, tc.ip+":8080") {
				t.Fatal("Binding without registered service doesn't refuse connections")
			}

			err = dp.RemoveBinding(tc.Binding)
			if err != nil {
				t.Fatal("Can't remove binding:", err)
			}

			if !testutil.CanDialNetNS(t, netns, network, tc.ip+":8080") {
				t.Fatal("Can't dial after removing the binding")
			}
		})
	}
}

func TestRemoveBinding(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, netns.Path())
	bindA := mustNewBinding(t, "foo", TCP, "::1", 80)
	bindB := mustNewBinding(t, "bar", TCP, "::1", 80)

	if err := dp.RemoveBinding(bindA); err == nil {
		t.Error("Removing a non-existing binding doesn't return an error")
	}

	if err := dp.AddBinding(bindA); err != nil {
		t.Fatal(err)
	}

	labels, err := dp.labels.List()
	if err != nil {
		t.Fatal(err)
	}

	if n := len(labels); n != 1 {
		t.Fatal("Expected one label, got", n)
	}

	if err := dp.RemoveBinding(bindB); err == nil {
		t.Fatal("Removed a binding where the label doesn't match")
	}

	if err := dp.RemoveBinding(bindA); err != nil {
		t.Fatal("Can't remove binding:", err)
	}

	labels, err = dp.labels.List()
	if err != nil {
		t.Fatal(err)
	}

	if n := len(labels); n != 0 {
		t.Fatal("Expected no labels, got", n)
	}
}

func TestRegisterSupportedSocketKind(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, netns.Path())

	networks := []string{
		"tcp4",
		"tcp6",
		"udp4",
		"udp6",
	}
	for _, net := range networks {
		t.Run(net, func(t *testing.T) {
			rawConn := mustNewLocalListener(t, net)
			err := dp.RegisterSocket("service-name", rawConn)
			if err != nil {
				t.Fatal("RegisterSocket failed:", err)
			}

			// TODO: Lookup registered socket
		})
	}
}

func TestUpdateRegisteredSocket(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, netns.Path())

	for i := 0; i < 3; i++ {
		rawConn := mustNewLocalListener(t, "tcp4")
		err := dp.RegisterSocket("service-name", rawConn)
		if err != nil {
			t.Fatalf("Can't RegisterSocket try #%d: %v", i+1, err)
		}
	}
}

func TestRegisterUnixSocket(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, netns.Path())

	networks := []string{
		"unix",
		"unixpacket",
		"unixgram",
	}
	for _, net := range networks {
		t.Run(net, func(t *testing.T) {
			rawConn := mustNewLocalListener(t, net)
			err := dp.RegisterSocket("service-name", rawConn)
			if err == nil {
				t.Fatal("RegisterSocket didn't fail")
			}
		})
	}
}

func TestRegisterConnectedTCP(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, netns.Path())

	ln, err := nettest.NewLocalListener("tcp4")
	if err != nil {
		t.Fatal("Can't Listen:", err)
	}
	defer ln.Close()

	laddr := ln.Addr()
	c, err := net.Dial(laddr.Network(), laddr.String())
	if err != nil {
		t.Fatal("Can't dial:", err)
	}
	defer c.Close()

	rc, err := c.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal("Can't get RawConn:", err)
	}
	err = dp.RegisterSocket("service-name", rc)
	if err == nil {
		t.Fatal("RegisterSocket didn't fail")
	}
}

func TestRegisterConnectedUDP(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, netns.Path())

	pc, err := nettest.NewLocalPacketListener("udp4")
	if err != nil {
		t.Fatal("Can't ListenPacket:", err)
	}
	defer pc.Close()

	laddr := pc.LocalAddr()
	c, err := net.Dial(laddr.Network(), laddr.String())
	if err != nil {
		t.Fatal("Can't dial:", err)
	}
	defer c.Close()

	rc, err := c.(*net.UDPConn).SyscallConn()
	if err != nil {
		t.Fatal("Can't get RawConn:", err)
	}
	err = dp.RegisterSocket("service-name", rc)
	if err == nil {
		t.Fatal("RegisterSocket didn't fail")
	}
}

func mustNewLocalListener(tb testing.TB, network string) syscall.RawConn {
	var sysConn syscall.Conn
	switch network {
	case "tcp4", "tcp6", "unix", "unixpacket":
		ln, err := nettest.NewLocalListener(network)
		if err != nil {
			tb.Fatal(err)
		}
		tb.Cleanup(func() { ln.Close() })

		sysConn = ln.(syscall.Conn)

	case "udp4", "udp6", "unixgram":
		c, err := nettest.NewLocalPacketListener(network)
		if err != nil {
			tb.Fatal(err)
		}
		tb.Cleanup(func() { c.Close() })

		sysConn = c.(syscall.Conn)
	}

	raw, err := sysConn.SyscallConn()
	if err != nil {
		tb.Fatal("Can't get raw conn:", err)
	}

	return raw
}

func mustNewBinding(tb testing.TB, label string, proto Protocol, prefix string, port uint16) *Binding {
	tb.Helper()

	bdg, err := NewBinding(label, proto, prefix, port)
	if err != nil {
		tb.Fatal("Can't create binding:", err)
	}

	return bdg
}

func mustCreateDispatcher(tb testing.TB, netns string) *Dispatcher {
	tb.Helper()

	dp, err := CreateDispatcher(netns, "/sys/fs/bpf")
	if err != nil {
		tb.Fatal("Can't create dispatcher:", err)
	}

	tb.Cleanup(func() { dp.Unload() })
	return dp
}

func mustOpenDispatcher(tb testing.TB, netns string) *Dispatcher {
	tb.Helper()

	dp, err := OpenDispatcher(netns, "/sys/fs/bpf")
	if err != nil {
		tb.Fatal("Can't open dispatcher:", err)
	}

	return dp
}
