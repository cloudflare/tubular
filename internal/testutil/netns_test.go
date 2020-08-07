package testutil

import (
	"os"
	"syscall"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
)

func TestNetNS(t *testing.T) {
	rootInode := getInode(t, "/proc/self/ns/")
	newNs := NewNetNS(t)
	if getInode(t, "/proc/self/ns/") != rootInode {
		t.Fatal("Call to NewNetNS changed network namespace")
	}

	newInode := getInode(t, newNs.Path())
	done := make(chan struct{})
	go func() {
		defer close(done)

		JoinNetNS(t, newNs)

		current, err := ns.GetCurrentNS()
		if err != nil {
			t.Error(err)
			return
		}

		if getInode(t, current.Path()) != newInode {
			t.Errorf("join() doesn't change network namespace")
		}
	}()

	<-done
}

func getInode(t *testing.T, path string) uint64 {
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatal("Can't stat:", err.Error())
	}
	return stat.Sys().(*syscall.Stat_t).Ino
}
