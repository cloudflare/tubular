package main

import (
	"sort"
	"testing"

	"code.cfops.it/sys/tubular/internal"
	"code.cfops.it/sys/tubular/internal/testutil"
	"github.com/google/go-cmp/cmp"
)

func TestBindUnbind(t *testing.T) {
	netns := mustReadyNetNS(t)

	if _, err := testTubectl(t, netns, "bind"); err == nil {
		t.Error("bind without arguments should return an error")
	}

	valid := [][]string{
		{"foo", "tcp", "127.0.0.1", "80"},
		{"foo", "udp", "::1", "443"},
		{"bar", "tcp", "fd00::/64", "443"},
	}

	for _, args := range valid {
		_, err := testTubectl(t, netns, "bind", args...)
		if err != nil {
			t.Errorf("Can't bind with args %q: %s", args, err)
		}
	}

	for _, args := range valid {
		_, err := testTubectl(t, netns, "unbind", args...)
		if err != nil {
			t.Errorf("Can't unbind with args %q: %s", args, err)
		}
	}
}

func TestBindInvariants(t *testing.T) {
	netns := mustReadyNetNS(t)

	_, err := testTubectl(t, netns, "unbind", "foo", "udp", "::1", "443")
	if err == nil {
		t.Error("Unbind doesn't return an error for non-existing binding")
	}

	_, err = testTubectl(t, netns, "bind", "foo", "udp", "::1", "443")
	if err != nil {
		t.Fatal(err)
	}

	dp := mustOpenDispatcher(t, netns)
	bindings, err := dp.Bindings()
	if err != nil {
		t.Fatal("Can't get bindings:", err)
	}

	if n := len(bindings); n != 1 {
		t.Error("Expected one binding, got", n)
	}

	bind := bindings[0]
	if bind.Label != "foo" {
		t.Error("Binding should have label foo, got", bind.Label)
	}
	if bind.Port != 443 {
		t.Error("Binding should have port 443, got", bind.Port)
	}
	if bind.Protocol != internal.UDP {
		t.Error("Binding should have proto UDP, got", bind.Protocol)
	}
	if p := bind.Prefix.String(); p != "::1/128" {
		t.Error("Binding should have prefix ::1/128, got", p)
	}
}

func TestBindInvalidInput(t *testing.T) {
	netns := mustReadyNetNS(t)

	// stp is not a valid transport protocol
	_, err := testTubectl(t, netns, "bind", "foo", "stp", "::1", "443")
	if err == nil {
		t.Error("Accepted invalid proto")
	}

	_, err = testTubectl(t, netns, "unbind", "foo", "stp", "::1", "443")
	if err == nil {
		t.Error("Accepted invalid proto")
	}

	_, err = testTubectl(t, netns, "bind", "foo", "udp", "::1", "111443")
	if err == nil {
		t.Error("Accepted invalid port")
	}

	_, err = testTubectl(t, netns, "unbind", "foo", "udp", "::1", "111443")
	if err == nil {
		t.Error("Accepted invalid port")
	}

	_, err = testTubectl(t, netns, "bind", "foo", "udp", "::ffff:192.0.2.128/96", "443")
	if err == nil {
		t.Error("Accepted v4-mapped prefix")
	}
}

func TestLoadBindings(t *testing.T) {
	netns := mustReadyNetNS(t)

	_, err := testTubectl(t, netns, "load-bindings", "testdata/invalid-bindings.json")
	if err == nil {
		t.Error("Invalid bindings json must return an error")
	}

	_, err = testTubectl(t, netns, "load-bindings", "testdata/bindings.json")
	if err != nil {
		t.Fatal("Can't load valid bindings:", err)
	}

	dp := mustOpenDispatcher(t, netns)
	bindings, err := dp.Bindings()
	if err != nil {
		t.Fatal("Can't get bindings:", err)
	}

	// These match testdata/bindings.json
	want := internal.Bindings{
		mustNewBinding(t, "foo", internal.TCP, "127.0.0.1", 0),
		mustNewBinding(t, "foo", internal.UDP, "127.0.0.1", 0),
		mustNewBinding(t, "foo-port", internal.TCP, "127.0.0.2", 53),
		mustNewBinding(t, "foo-port", internal.UDP, "127.0.0.2", 53),
		mustNewBinding(t, "bar", internal.TCP, "::1/64", 0),
		mustNewBinding(t, "bar", internal.UDP, "::1/64", 0),
		mustNewBinding(t, "bar-port", internal.TCP, "1::1/64", 53),
		mustNewBinding(t, "bar-port", internal.UDP, "1::1/64", 53),
	}

	sort.Sort(bindings)
	sort.Sort(want)

	if diff := cmp.Diff(want, bindings, testutil.IPComparer()); diff != "" {
		t.Errorf("Bindings don't match (+y -x):\n%s", diff)
	}
}

func mustNewBinding(tb testing.TB, label string, proto internal.Protocol, prefix string, port uint16) *internal.Binding {
	tb.Helper()

	bind, err := internal.NewBinding(label, proto, prefix, port)
	if err != nil {
		tb.Fatal("Can't create binding:", err)
	}

	return bind
}
