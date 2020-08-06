package internal

import (
	"fmt"
	"os"
	"testing"

	"code.cfops.it/sys/tubular/internal/testutil"
)

func TestMain(m *testing.M) {
	testutil.ExecuteInNetns()

	if err := SetLockedMemoryLimits(10 * 1024 * 1024); err != nil {
		fmt.Fprintln(os.Stderr, "Can't raise rlimit, tests may fail:", err)
	}
	os.Exit(m.Run())
}

func TestLoadDispatcher(t *testing.T) {
	dp, err := CreateDispatcher("/proc/self/ns/net", "/sys/fs/bpf")
	if err != nil {
		t.Fatal("Can't create dispatcher:", err)
	}

	if err := dp.Close(); err != nil {
		t.Fatal("Can't close dispatcher:", err)
	}

	if _, err := os.Stat(dp.Path); err != nil {
		t.Error("State directory doesn't exist:", err)
	}

	dp, err = OpenDispatcher("/proc/self/ns/net", "/sys/fs/bpf")
	if err != nil {
		t.Fatal("Can't open dispatcher:", err)
	}
	defer dp.Close()

	if err := dp.Unload(); err != nil {
		t.Fatal("Can't unload:", err)
	}

	if _, err := os.Stat(dp.Path); err == nil {
		t.Error("State directory remains after unload")
	}

	// TODO: Check that program is detached
}
