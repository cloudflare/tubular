package main

import (
	"bytes"
	"os"
	"testing"

	"code.cfops.it/sys/tubular/internal"
	"code.cfops.it/sys/tubular/internal/testutil"
	_ "code.cfops.it/sys/tubular/internal/testutil"
	"github.com/containernetworking/plugins/pkg/ns"
)

func testTubectl(tb testing.TB, netns ns.NetNS, cmd string, args ...string) error {
	args = append([]string{
		"-netns", netns.Path(),
		cmd,
	}, args...)

	stdio := new(bytes.Buffer)
	if err := tubectl(stdio, stdio, args...); err != nil {
		tb.Helper()
		if stdio.Len() > 0 {
			tb.Logf("Output:\n%s", stdio.String())
		}
		return err
	}
	return nil
}

func mustTestTubectl(tb testing.TB, netns ns.NetNS, cmd string, args ...string) {
	if err := testTubectl(tb, netns, cmd, args...); err != nil {
		tb.Helper()
		tb.Fatal("Can't execute tubectl:", err)
	}
}

func mustReadyNetNS(tb testing.TB) ns.NetNS {
	tb.Helper()

	netns := testutil.NewNetNS(tb)
	dp, err := internal.CreateDispatcher(netns.Path(), "/sys/fs/bpf")
	if err != nil {
		tb.Fatal(err)
	}
	path := dp.Path
	if err := dp.Close(); err != nil {
		tb.Fatal("Can't close dispatcher:", err)
	}
	tb.Cleanup(func() { os.RemoveAll(path) })
	return netns
}

func mustOpenDispatcher(tb testing.TB, netns ns.NetNS) *internal.Dispatcher {
	tb.Helper()
	dp, err := internal.OpenDispatcher(netns.Path(), "/sys/fs/bpf")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { dp.Close() })
	return dp
}
