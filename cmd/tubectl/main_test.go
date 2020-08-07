package main

import (
	"bytes"
	"testing"

	_ "code.cfops.it/sys/tubular/internal/testutil"
	"github.com/containernetworking/plugins/pkg/ns"
)

func testTubectl(tb testing.TB, netns ns.NetNS, args ...string) error {
	args = append([]string{
		"-netns", netns.Path(),
	}, args...)

	stdio := new(bytes.Buffer)
	if err := tubectl(stdio, stdio, args...); err != nil {
		tb.Helper()
		tb.Logf("Output:\n%s", stdio.String())
		return err
	}
	return nil
}

func mustTestTubectl(tb testing.TB, netns ns.NetNS, args ...string) {
	if err := testTubectl(tb, netns, args...); err != nil {
		tb.Helper()
		tb.Fatal("Can't execute tubectl:", err)
	}
}
