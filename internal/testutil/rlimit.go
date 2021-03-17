package testutil

import (
	"fmt"
	"os"

	"code.cfops.it/sys/tubular/internal/rlimit"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

const lockedMemoryLimit = 100 * 1024 * 1024

func init() {
	err := WithCapabilities(func() error {
		return rlimit.SetLockedMemoryLimits(lockedMemoryLimit)
	}, cap.SYS_RESOURCE)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Can't raise rlimit, tests may fail:", err)
	}
}
