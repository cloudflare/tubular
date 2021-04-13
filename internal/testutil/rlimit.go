package testutil

import (
	"fmt"
	"math"
	"os"

	"code.cfops.it/sys/tubular/internal/rlimit"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

func init() {
	err := WithCapabilities(func() error {
		// We need -1 here for TestUnprivilegedMode
		return rlimit.SetLockedMemoryLimits(math.MaxUint64 - 1)
	}, cap.SYS_RESOURCE)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Can't raise rlimit, tests may fail:", err)
	}
}
