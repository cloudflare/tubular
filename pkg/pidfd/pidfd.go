package pidfd

import (
	"errors"
	"fmt"
	"os"

	"code.cfops.it/sys/tubular/pkg/sysconn"

	"golang.org/x/sys/unix"
)

// Files enumerates all open files of another process.
//
// filter controls which files will be returned.
func Files(pid int, ps ...sysconn.Predicate) (files []*os.File, err error) {
	const maxFDGap = 32

	defer func() {
		if err != nil {
			for _, file := range files {
				file.Close()
			}
		}
	}()

	if pid == 0 || pid == os.Getpid() {
		// Retrieving files from the current process makes the loop below
		// never finish.
		return nil, fmt.Errorf("can't retrieve files from the same process")
	}

	pidfd, err := pidfdOpen(pid, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(pidfd)

	for i, gap := 0, 0; i < int(^uint(0)>>1) && gap < maxFDGap; i++ {
		target, err := pidfdGetFD(pidfd, i, 0)
		if errors.Is(err, unix.EBADF) {
			gap++
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("target fd %d: %s", i, err)
		}
		gap = 0

		keep, err := sysconn.FilterFd(target, ps...)
		if err != nil {
			unix.Close(target)
			return nil, fmt.Errorf("target fd %d: %w", i, err)
		} else if keep {
			files = append(files, os.NewFile(uintptr(target), ""))
		} else {
			unix.Close(target)
		}
	}

	return files, nil
}

func pidfdOpen(pid, flags int) (int, error) {
	fd, _, errNo := unix.Syscall(unix.SYS_PIDFD_OPEN, uintptr(pid), uintptr(flags), 0)
	if errNo != 0 {
		return -1, fmt.Errorf("pidfd_open(%d): %w", pid, errNo)
	}
	return int(fd), nil
}

func pidfdGetFD(pidfd, target, flags int) (int, error) {
	fd, _, errNo := unix.Syscall(unix.SYS_PIDFD_GETFD, uintptr(pidfd), uintptr(target), uintptr(flags))
	if errNo != 0 {
		return -1, fmt.Errorf("pidfd_getfd(%d, %d): %w", pidfd, target, errNo)
	}
	return int(fd), nil
}
