package testutil

import (
	"math"
	"testing"
	"time"

	"github.com/cloudflare/tubular/internal/rlimit"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

func init() {
	EnterUnprivilegedMode()
}

func TestUnprivilegedMode(t *testing.T) {
	// EnterUnprivilegedMode should cause setrlimit to fail.
	if err := rlimit.SetLockedMemoryLimits(math.MaxUint64); err == nil {
		t.Fatal("setrlimit should fail due to missing capabilities")
	}
}

func TestWithCapabilities(t *testing.T) {
	err := WithCapabilities(func() error {
		return rlimit.SetLockedMemoryLimits(math.MaxUint64)
	}, cap.SYS_RESOURCE)
	if err != nil {
		t.Error("Effective capabilities aren't granted")
	}
}

func TestWithCapabilitiesConcurrent(t *testing.T) {
	quit := make(chan struct{})
	defer close(quit)

	ready := make(chan struct{}, 1)
	fn := func() {
		t.Helper()

		err := WithCapabilities(func() error {
			ready <- struct{}{}
			<-quit
			return nil
		})
		if err != nil {
			t.Error(err)
		}
	}

	go fn()
	<-ready

	go fn()
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("Can't launch concurrent goroutines")
	}
}
