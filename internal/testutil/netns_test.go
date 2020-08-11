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
	if newInode == rootInode {
		t.Fatal("NewNetNS doesn't create a new network namespace")
	}

	JoinNetNS(t, newNs, func() {
		current, err := ns.GetCurrentNS()
		if err != nil {
			t.Fatal(err)
		}

		if getInode(t, current.Path()) != newInode {
			t.Fatal("JoinNetNS() doesn't change network namespace")
		}
	})
}

func TestCanDialNetNS(t *testing.T) {
	netns := NewNetNS(t)

	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			if CanDialNetNS(t, netns, network, "127.0.0.1:8080") {
				t.Fatal("Can dial in empty network namespace")
			}

			if CanDialNetNS(t, netns, network, "127.0.0.1:8080") {
				t.Fatal("Can dial a second time in empty network namespace")
			}

			ListenNetNS(t, netns, network, "127.0.0.1:8080")

			if !CanDialNetNS(t, netns, network, "127.0.0.1:8080") {
				t.Fatal("Can't dial with listener present")
			}

			if !CanDialNetNS(t, netns, network, "127.0.0.1:8080") {
				t.Fatal("Can't dial a second time with listener present")
			}
		})
	}
}

func getInode(t *testing.T, path string) uint64 {
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatal("Can't stat:", err.Error())
	}
	return stat.Sys().(*syscall.Stat_t).Ino
}
