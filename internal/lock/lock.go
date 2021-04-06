// Package lock is a wrapper for file description locks.
package lock

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// File is a flock() based avisory file lock.
//
// dup()ed file descriptors share the same file description, and so share the
// same lock.
type File struct {
	*os.File
	raw syscall.RawConn
	how int
}

var _ sync.Locker = (*File)(nil)

// Exclusive creates a new exclusive lock.
//
// Returns an unlocked lock.
func Exclusive(file *os.File) (*File, error) {
	raw, err := file.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("lock exclusive: %s", err)
	}

	return &File{file, raw, unix.LOCK_EX}, nil
}

// OpenLockedExclusive opens the given path and acquires an exclusive lock.
func OpenLockedExclusive(path string) (*File, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	lock, err := Exclusive(file)
	if err != nil {
		return nil, err
	}

	lock.Lock()
	return lock, nil
}

// Shared creates a new shared lock.
//
// The lock is implicitly released when the file description of file is closed.
//
// Returns an unlocked lock.
func Shared(file *os.File) (*File, error) {
	raw, err := file.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("lock exclusive: %s", err)
	}

	return &File{file, raw, unix.LOCK_SH}, nil
}

// OpenShared opens the given path and acquires a shared lock.
func OpenLockedShared(path string) (*File, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	lock, err := Shared(file)
	if err != nil {
		return nil, err
	}

	lock.Lock()
	return lock, nil
}

// Lock implements sync.Locker.
//
// It panics if the underlying syscalls return an error.
func (fl *File) Lock() {
	if err := fl.flock(fl.how); err != nil {
		panic(err.Error())
	}
}

// Unlock implements sync.Locker.
//
// It panics if the underlying syscalls return an error.
func (fl *File) Unlock() {
	if err := fl.flock(unix.LOCK_UN); err != nil {
		panic(err.Error())
	}
}

func (fl *File) flock(how int) error {
	var flockErr error
	err := fl.raw.Control(func(fd uintptr) {
		for {
			flockErr = unix.Flock(int(fd), how)
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
		return fmt.Errorf("lock exclusive: acquire fd: %s", err)
	}
	return flockErr
}
