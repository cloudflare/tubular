package testutil

import (
	"fmt"
	"os"
	"syscall"
	"testing"
)

func TestExecuteInNetns(t *testing.T) {
	old := os.Getenv("OLD_NETNS_INODE")
	current := fmt.Sprint(currentNetNSInode())

	if current == old {
		t.Errorf("Didn't switch into new namespace, %s == %s", current, old)
	}
}

func TestMain(m *testing.M) {
	if os.Getenv("OLD_NETNS_INODE") == "" {
		os.Setenv("OLD_NETNS_INODE", fmt.Sprint(currentNetNSInode()))
	}
	ExecuteInNetns()
	os.Exit(m.Run())
}

func currentNetNSInode() uint64 {
	stat, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		panic("Can't stat:" + err.Error())
	}
	return stat.Sys().(*syscall.Stat_t).Ino
}
