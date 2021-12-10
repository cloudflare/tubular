package testutil

import (
	"os"
	"syscall"
	"testing"
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

	var changedInode uint64
	JoinNetNS(t, newNs, func() error {
		changedInode = getInode(t, CurrentNetNS(t).Path())
		return nil
	})

	if changedInode != newInode {
		t.Fatal("JoinNetNS() doesn't change network namespace")
	}
}

func TestCanDial(t *testing.T) {
	netns := NewNetNS(t, "ab::/64", "192.0.2.0/24")

	for network, addr := range map[string]string{
		"tcp":  "192.0.2.1:4242",
		"udp":  "192.0.2.1:4242",
		"tcp4": "192.0.2.1:4242",
		"udp4": "192.0.2.1:4242",
		"tcp6": "[ab::1]:4242",
		"udp6": "[ab::1]:4242",
	} {
		t.Run(network, func(t *testing.T) {
			if CanDial(t, netns, network, addr) {
				t.Fatal("Can dial in empty network namespace")
			}

			if CanDial(t, netns, network, addr) {
				t.Fatal("Can dial a second time in empty network namespace")
			}

			ListenAndEchoWithName(t, netns, network, addr, "testing")

			if !CanDial(t, netns, network, addr) {
				t.Fatal("Can't dial with listener present")
			}

			if !CanDial(t, netns, network, addr) {
				t.Fatal("Can't dial a second time with listener present")
			}

			Dial(t, netns, network, addr)
			CanDialName(t, netns, network, addr, "testing")
		})
	}
}

func getInode(t *testing.T, path string) uint64 {
	t.Helper()

	stat, err := os.Stat(path)
	if err != nil {
		t.Fatal("Can't stat:", err.Error())
	}
	return stat.Sys().(*syscall.Stat_t).Ino
}
