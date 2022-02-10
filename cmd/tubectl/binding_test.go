package main

import (
	"sort"
	"strings"
	"testing"

	"code.cfops.it/sys/tubular/internal"
	"code.cfops.it/sys/tubular/internal/testutil"
	"github.com/google/go-cmp/cmp"
)

func TestBindings(t *testing.T) {
	netns := mustReadyNetNS(t)

	bindings := map[string]struct {
		proto  internal.Protocol
		prefix string
		port   uint16
	}{
		"foo":  {internal.TCP, "::1", 80},
		"bar":  {internal.TCP, "1::", 443},
		"baz":  {internal.UDP, "127.0.1.0/24", 443},
		"boo":  {internal.UDP, "::1", 443},
		"wild": {internal.UDP, "2::1", 0},
	}

	{
		dp := mustOpenDispatcher(t, netns)
		for label, bind := range bindings {
			mustAddBinding(t, dp, label, bind.proto, bind.prefix, bind.port)
		}
		dp.Close()
	}

	set := func(strs ...string) map[string]struct{} {
		result := make(map[string]struct{})
		for _, str := range strs {
			result[str] = struct{}{}
		}
		return result
	}

	for _, test := range []struct {
		args   []string
		labels map[string]struct{}
	}{
		{[]string{}, set("foo", "bar", "baz", "boo", "wild")},
		{[]string{"tcp", "::/0"}, set("foo", "bar")},
		{[]string{"tcp", "::/16"}, set("foo")},
		{[]string{"tcp", "::/0", "443"}, set("bar")},
		{[]string{"udp", "0.0.0.0/0"}, set("baz")},
		{[]string{"any", "::/0", "443"}, set("bar", "boo", "wild")},
		{[]string{"udp", "2::1", "443"}, set("wild")},
	} {
		t.Run(strings.Join(test.args, " "), func(t *testing.T) {
			output, err := testTubectl(t, netns, "bindings", test.args...)
			if err != nil {
				t.Fatal(err)
			}

			outputStr := output.String()
			for label := range bindings {
				if _, ok := test.labels[label]; ok {
					if !strings.Contains(outputStr, label) {
						t.Error("Output doesn't contain label", label)
					}
				} else {
					if strings.Contains(outputStr, label) {
						t.Error("Output contains label", label)
					}
				}
			}
		})
	}
}

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

	output, err := testTubectl(t, netns, "load-bindings", "testdata/bindings.json")
	if err != nil {
		t.Fatal("Can't load valid bindings:", err)
	}
	if output.Len() == 0 {
		t.Error("Loading bindings doesn't produce output")
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

	if diff := cmp.Diff(want, bindings, testutil.IPPrefixComparer()); diff != "" {
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
