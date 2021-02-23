package main

import (
	"testing"

	"code.cfops.it/sys/tubular/internal"
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
