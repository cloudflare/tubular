package internal

import (
	"fmt"
	"os"
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
