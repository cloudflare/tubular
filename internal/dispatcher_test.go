package internal

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"

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
			testutil.Listen(t, netns, network, tc.ip+":8080")

			if !testutil.CanDial(t, netns, network, tc.ip+":8080") {
				t.Fatal("Can't dial before creating the binding")
			}

			err := dp.AddBinding(tc.Binding)
			if err != nil {
				t.Fatal("Can't create binding:", err)
			}

			if testutil.CanDial(t, netns, network, tc.ip+":8080") {
				t.Fatal("Binding without registered service doesn't refuse connections")
			}

			err = dp.RemoveBinding(tc.Binding)
			if err != nil {
				t.Fatal("Can't remove binding:", err)
			}

			if !testutil.CanDial(t, netns, network, tc.ip+":8080") {
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

	dests, err := dp.destinations.List()
	if err != nil {
		t.Fatal(err)
	}

	if n := len(dests); n != 1 {
		t.Fatal("Expected one destination, got", n)
	}

	if err := dp.RemoveBinding(bindB); err == nil {
		t.Fatal("Removed a binding where the destination doesn't match")
	}

	if err := dp.RemoveBinding(bindA); err != nil {
		t.Fatal("Can't remove binding:", err)
	}

	dests, err = dp.destinations.List()
	if err != nil {
		t.Fatal(err)
	}

	if n := len(dests); n != 0 {
		t.Fatal("Expected no destinations, got", n)
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
	for _, network := range networks {
		t.Run(network, func(t *testing.T) {
			conn := testutil.Listen(t, netns, network, "")
			created, err := dp.RegisterSocket("service-name", conn)
			if err != nil {
				t.Fatal("RegisterSocket failed:", err)
			}

			if !created {
				t.Error("RegisterSocket doesn't return true for new sockets")
			}

			// TODO: Lookup registered socket
		})
	}
}

func TestUpdateRegisteredSocket(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, netns.Path())

	for i := 0; i < 3; i++ {
		conn := testutil.Listen(t, netns, "tcp4", "")
		created, err := dp.RegisterSocket("service-name", conn)
		if err != nil {
			t.Fatalf("Can't RegisterSocket try #%d: %v", i+1, err)
		}

		if i > 0 && created {
			t.Errorf("Created is true on trd #%d", i+1)
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
	for _, network := range networks {
		t.Run(network, func(t *testing.T) {
			conn := testutil.Listen(t, netns, network, "")
			_, err := dp.RegisterSocket("service-name", conn)
			if err == nil {
				t.Fatal("RegisterSocket didn't fail")
			}
		})
	}
}

func TestRegisterConnectedSocket(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, netns.Path())

	networks := []string{
		"tcp4",
		"udp4",
	}

	for _, network := range networks {
		t.Run(network, func(t *testing.T) {
			testutil.Listen(t, netns, network, "127.0.0.1:1234")
			conn := testutil.Dial(t, netns, network, "127.0.0.1:1234")

			_, err := dp.RegisterSocket("service-name", conn)
			if err == nil {
				t.Fatal("RegisterSocket didn't fail")
			}
		})
	}
}

func TestMetrics(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, netns.Path())
	ln := testutil.Listen(t, netns, "tcp4", "").(*net.TCPListener)

	bind := mustNewBinding(t, "foo", TCP, "127.0.0.1", 8080)
	if err := dp.AddBinding(bind); err != nil {
		t.Fatal("Can't add binding:", err)
	}

	if testutil.CanDial(t, netns, "tcp4", "127.0.0.1:8080") {
		t.Fatal("Could dial before adding socket")
	}

	if _, err := dp.RegisterSocket("foo", ln); err != nil {
		t.Fatal("Can't add socket:", err)
	}

	if !testutil.CanDial(t, netns, "tcp4", "127.0.0.1:8080") {
		t.Fatal("Can't dial after adding socket")
	}

	raw, err := ln.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}

	dest, err := newDestinationFromConn("foo", raw)
	if err != nil {
		t.Fatal(err)
	}

	metrics, err := dp.Metrics()
	if err != nil {
		t.Fatal("Can't get metrics:", err)
	}

	destMetrics, ok := metrics.Destinations[*dest]
	if !ok {
		t.Fatal("No metrics for", dest)
	}

	if destMetrics.ReceivedPackets != 2 {
		t.Error("Expected two packets, got", destMetrics.ReceivedPackets)
	}

	if destMetrics.DroppedPacketsMissingSocket != 1 {
		t.Error("Expected one missing socket packet, got", destMetrics.DroppedPacketsMissingSocket)
	}

	if destMetrics.DroppedPacketsIncompatibleSocket != 0 {
		t.Error("Expected no incompatible socket packet, got", destMetrics.DroppedPacketsIncompatibleSocket)
	}

	// Remove the socket from the sockmap
	ln.Close()

	if err := dp.RemoveBinding(bind); err != nil {
		t.Fatal("Can't remove binding:", err)
	}

	// New binding should re-use ID
	bind2 := mustNewBinding(t, "foo", UDP, "127.0.0.1", 443)
	if err := dp.AddBinding(bind2); err != nil {
		t.Fatal("Can't add second binding:", err)
	}

	dest = newDestinationFromBinding(bind2)
	metrics, err = dp.Metrics()
	if err != nil {
		t.Fatal("Can't get metrics:", err)
	}

	destMetrics, ok = metrics.Destinations[*dest]
	if !ok {
		t.Fatal("No metrics for", dest)
	}

	if destMetrics.ReceivedPackets != 0 {
		t.Error("Expected zero packets, got", destMetrics.ReceivedPackets)
	}

	if destMetrics.DroppedPacketsMissingSocket != 0 {
		t.Error("Expected zero missing socket packet, got", destMetrics.DroppedPacketsMissingSocket)
	}

	if destMetrics.DroppedPacketsIncompatibleSocket != 0 {
		t.Error("Expected zero incompatible socket packet, got", destMetrics.DroppedPacketsIncompatibleSocket)
	}
}

func TestBindingPrecedence(t *testing.T) {
	netns := testutil.NewNetNS(t, "1.2.3.0/24", "4.3.2.0/24")
	dp := mustCreateDispatcher(t, netns.Path())

	testcases := []*Binding{
		mustNewBinding(t, "spectrum", TCP, "1.2.3.0/24", 0),
		// Port takes prededence over wildcard.
		mustNewBinding(t, "nginx-ssl", TCP, "1.2.3.0/24", 443),
		// More specific prefix takes precedence.
		mustNewBinding(t, "spectrum", TCP, "1.2.3.4/32", 0),
		// More specific prefix with port takes precedence.
		mustNewBinding(t, "nginx-ssl", TCP, "1.2.3.4/32", 80),
		mustNewBinding(t, "nginx-ssl", TCP, "4.3.2.0/24", 443),
		mustNewBinding(t, "new-tls-thing", TCP, "4.3.2.0/25", 443),
	}

	listeners := make(map[string]syscall.Conn)
	for i, bind := range testcases {
		if err := dp.AddBinding(bind); err != nil {
			t.Fatal("Can't add binding", i, bind, err)
		}

		if listeners[bind.Label] != nil {
			continue
		}

		ln := testutil.ListenWithName(t, netns, bind.Protocol.String(), "127.0.0.1:0", bind.Label)
		listeners[bind.Label] = ln

		if _, err := dp.RegisterSocket(bind.Label, ln); err != nil {
			t.Fatal("Can't register listener:", err)
		}
	}

	for _, test := range []struct {
		address string
		label   string
	}{
		{"1.2.3.1:80", "spectrum"},
		{"1.2.3.1:81", "spectrum"},
		{"1.2.3.1:443", "nginx-ssl"},
		{"1.2.3.4:443", "spectrum"},
		{"1.2.3.4:80", "nginx-ssl"},
		{"4.3.2.1:443", "new-tls-thing"},
		{"4.3.2.128:443", "nginx-ssl"},
	} {
		testutil.CanDialName(t, netns, "tcp", test.address, test.label)
	}
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
