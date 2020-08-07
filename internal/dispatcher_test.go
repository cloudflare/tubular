package internal

import (
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

func mustCreateDispatcher(tb testing.TB, netns string) *Dispatcher {
	tb.Helper()

	dp, err := CreateDispatcher(netns, "/sys/fs/bpf")
	if err != nil {
		tb.Fatal("Can't create dispatcher:", err)
	}

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
