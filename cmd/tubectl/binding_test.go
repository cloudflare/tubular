package main

import (
	"testing"

	"code.cfops.it/sys/tubular/internal"
)

func TestBind(t *testing.T) {
	netns := mustReadyNetNS(t)

	if _, err := testTubectl(t, netns, "bind"); err == nil {
		t.Error("bind without arguments should return an error")
	}

	for _, args := range [][]string{
		{"foo", "tcp", "127.0.0.1", "80"},
		{"foo", "udp", "::1", "443"},
		{"bar", "tcp", "fd00::/64", "443"},
	} {
		_, err := testTubectl(t, netns, "bind", args...)
		if err != nil {
			t.Errorf("Can't bind with args %q: %s", args, err)
		}
	}

	dp := mustOpenDispatcher(t, netns)
	bindings, err := dp.Bindings()
	if err != nil {
		t.Fatal("Can't get bindings:", err)
	}

	if n := len(bindings); n != 3 {
		t.Error("Expected three bindings, got", n)
	}

	bind := bindings[0]
	if bind.Label != "bar" {
		t.Error("Binding should have label bar, got", bind.Label)
	}
	if bind.Port != 443 {
		t.Error("Binding should have port 443, got", bind.Port)
	}
	if bind.Protocol != internal.TCP {
		t.Error("Binding should have proto TCP, got", bind.Protocol)
	}
	if p := bind.Prefix.String(); p != "fd00::/64" {
		t.Error("Binding should have prefix fd00::/64, got", p)
	}
}
