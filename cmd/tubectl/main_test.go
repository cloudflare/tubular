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

func testTubectl(tb testing.TB, netns ns.NetNS, cmd string, args ...string) (*bytes.Buffer, error) {
	tb.Helper()

	args = append([]string{
		"-netns", netns.Path(),
		cmd,
	}, args...)

	output := new(bytes.Buffer)
	if err := tubectl(output, output, args); err != nil {

		return output, err
	}
	return output, nil
}

func mustTestTubectl(tb testing.TB, netns ns.NetNS, cmd string, args ...string) {
	tb.Helper()

	if output, err := testTubectl(tb, netns, cmd, args...); err != nil {
		if output.Len() > 0 {
			tb.Logf("Output:\n%s", output.String())
		}
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

func mustAddBinding(tb testing.TB, dp *internal.Dispatcher, label string, proto internal.Protocol, prefix string, port uint16) {
	tb.Helper()

	bind, err := internal.NewBinding(label, proto, prefix, port)
	if err != nil {
		tb.Fatal(err)
	}

	err = dp.AddBinding(bind)
	if err != nil {
		tb.Fatal("Can't add binding:", err)
	}
}
