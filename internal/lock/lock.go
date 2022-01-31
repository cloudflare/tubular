// Package lock is a wrapper for file description locks.
package lock

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"code.cfops.it/sys/tubular/pkg/sysconn"

	"golang.org/x/sys/unix"
)

// File is a flock() based avisory file lock.
//
// dup()ed file descriptors share the same file description, and so share the
// same lock.
type File struct {
	*os.File
	how int
}

var _ sync.Locker = (*File)(nil)

// Exclusive creates a new exclusive lock.
//
// Returns an unlocked lock.
func Exclusive(file *os.File) *File {
	return &File{file, unix.LOCK_EX}
}

// OpenLockedExclusive opens the given path and acquires an exclusive lock.
func OpenLockedExclusive(path string) (*File, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	lock := Exclusive(file)
	lock.Lock()
	return lock, nil
}

// Shared creates a new shared lock.
//
// The lock is implicitly released when the file description of file is closed.
//
// Returns an unlocked lock.
func Shared(file *os.File) *File {
	return &File{file, unix.LOCK_SH}
}

// OpenShared opens the given path and acquires a shared lock.
func OpenLockedShared(path string) (*File, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	lock := Shared(file)
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

// TryLock attempts to lock the file without blocking.
//
// It panics if the underlying syscalls return an error.
func (fl *File) TryLock() bool {
	err := fl.flock(fl.how | unix.LOCK_NB)
	if err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return false
		}

		panic(err.Error())
	}
	return true
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
	err := sysconn.Control(fl.File, func(fd int) (err error) {
		for {
			err = unix.Flock(int(fd), how)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return
		}
	})

	if err != nil {
		return fmt.Errorf("flock: %w", err)
	}
	return nil
}
