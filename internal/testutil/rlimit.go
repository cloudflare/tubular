package testutil

import (
	"fmt"
	"os"

	"code.cfops.it/sys/tubular/internal/rlimit"
)

func init() {
	if err := rlimit.SetLockedMemoryLimits(100 * 1024 * 1024); err != nil {
		fmt.Fprintln(os.Stderr, "Can't raise rlimit, tests may fail:", err)
	}
}
