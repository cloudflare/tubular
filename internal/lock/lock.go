// Package lock is a wrapper for file description locks.
package lock

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// TryLockExclusive places an exclusive advisory file lock on fd.
//
// The lock is released when fd is closed.
//
// Returns unix.EWOULDBLOCK if fd is already locked.
func TryLockExclusive(file *os.File) error {
	raw, err := file.SyscallConn()
	if err != nil {
		return fmt.Errorf("lock exclusive: %s", err)
	}

	var flockErr error
	err = raw.Control(func(fd uintptr) {
		for {
			flockErr = unix.Flock(int(fd), unix.LOCK_EX|unix.LOCK_NB)
			if errors.Is(flockErr, unix.EINTR) {
				continue
			}
			if flockErr != nil {
				flockErr = fmt.Errorf("lock exclusive: %w", flockErr)
			}
			return
		}
	})
	if err != nil {
		return fmt.Errorf("lock exclusive: %s", err)
	}
	return flockErr
}
