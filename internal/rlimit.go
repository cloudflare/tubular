package internal

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// SetLockedMemoryLimits sets an upper bound on the amount
// of locked memory the current user may use.
func SetLockedMemoryLimits(lockedMemoryLimit uint64) error {
	err := syscall.Setrlimit(unix.RLIMIT_MEMLOCK, &syscall.Rlimit{
		Cur: lockedMemoryLimit,
		Max: lockedMemoryLimit,
	})
	if err != nil {
		return fmt.Errorf("can't adjust RLIMIT_MEMLOCK: %s", err)
	}

	return nil
}
