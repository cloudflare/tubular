package internal

import (
	"fmt"
	"net"
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

func TestOverlappingBindings(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, netns.Path())

	prefixA := mustParseIPNet(t, "127.0.0.1/32")
	if err := dp.AddBinding("foo", tcpProto, prefixA, 8080); err != nil {
		t.Fatal("can't add /32:", err)
	}

	prefixB := mustParseIPNet(t, "127.0.0.1/24")
	if err := dp.AddBinding("bar", tcpProto, prefixB, 8080); err != nil {
		t.Fatal("can't add /24:", err)
	}

	if err := dp.AddBinding("bar", tcpProto, prefixB, 8080); err == nil {
		t.Error("Bindings can be added multiple times")
	}

	// TODO: Check that connections reach the correct service.
}

func TestAddAndRemoveBindings(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, netns.Path())

	testcases := []struct {
		proto  Protocol
		ip     string
		prefix string
	}{
		{tcpProto, "127.0.0.1", "127.0.0.1/8"},
		{udpProto, "127.0.0.1", "127.0.0.1/8"},
		{tcpProto, "[::1]", "::1/128"},
		{udpProto, "[::1]", "::1/128"},
	}

	for _, tc := range testcases {
		name := fmt.Sprintf("%v %s", tc.proto, tc.ip)
		t.Run(name, func(t *testing.T) {
			network := tc.proto.network()
			testutil.ListenNetNS(t, netns, network, tc.ip+":8080")

			if !testutil.CanDialNetNS(t, netns, network, tc.ip+":8080") {
				t.Fatal("Can't dial before creating the binding")
			}

			prefix := mustParseIPNet(t, tc.prefix)
			err := dp.AddBinding("foo", tc.proto, prefix, 8080)
			if err != nil {
				t.Fatal("Can't create binding:", err)
			}

			if testutil.CanDialNetNS(t, netns, network, tc.ip+":8080") {
				t.Fatal("Binding without registered service doesn't refuse connections")
			}

			err = dp.RemoveBinding(tc.proto, prefix, 8080)
			if err != nil {
				t.Fatal("Can't remove binding:", err)
			}

			if !testutil.CanDialNetNS(t, netns, network, tc.ip+":8080") {
				t.Fatal("Can't dial after removing the binding")
			}
		})
	}
}

func mustParseIPNet(tb testing.TB, cidr string) *net.IPNet {
	tb.Helper()

	_, ipn, err := net.ParseCIDR(cidr)
	if err != nil {
		tb.Fatal("Can't parse CIDR:", err)
	}

	return ipn
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
