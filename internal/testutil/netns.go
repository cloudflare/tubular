package testutil

import (
	"fmt"
	"os/exec"
	"runtime"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"golang.org/x/sys/unix"
)

// NewNetNS creates a pristine network namespace.
func NewNetNS(tb testing.TB) ns.NetNS {
	tb.Helper()

	quit := make(chan struct{})
	result := make(chan ns.NetNS, 1)
	errs := make(chan error, 1)
	go func() {
		// We never unlock the OS thread, which has the effect
		// of terminating the thread after the current goroutine
		// exits. This is desirable to avoid other goroutines
		// executing in the wrong namespace.
		runtime.LockOSThread()

		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			errs <- fmt.Errorf("unshare: %s", err)
			return
		}

		ip := exec.Command("ip", "link", "set", "dev", "lo", "up")
		if out, err := ip.CombinedOutput(); err != nil {
			if len(out) > 0 {
				tb.Log(string(out))
			}
			errs <- fmt.Errorf("set up loopback: %s", err)
			return
		}

		netns, err := ns.GetCurrentNS()
		if err != nil {
			errs <- fmt.Errorf("get current network namespace: %s", err)
			return
		}

		result <- netns

		// Block the goroutine (and the thread) until the
		// network namespace isn't needed anymore.
		<-quit
	}()

	select {
	case err := <-errs:
		tb.Fatal(err)
		return nil

	case netns := <-result:
		tb.Cleanup(func() {
			close(quit)
			netns.Close()
		})

		return netns
	}
}

// JoinNetNS moves the current goroutine to a different network namespace.
//
// Any goroutines invoked from the moved goroutine will still execute in the
// parent network namespace.
func JoinNetNS(tb testing.TB, netns ns.NetNS) {
	tb.Helper()

	runtime.LockOSThread()
	if err := netns.Set(); err != nil {
		// tb.Fatal mustn't be called from a different goroutine,
		// so we call Goexit explicitly after flagging an error.
		tb.Error("Can't join netns:", err)
		runtime.Goexit()
	}
}
