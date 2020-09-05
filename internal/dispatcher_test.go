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
