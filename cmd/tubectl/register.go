package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"syscall"
)

const (
	listenFdsStart = 3 // SD_LISTEN_FDS_START
)

func register(e *env, args ...string) error {
	set := e.newFlagSet("register", `<label>

Registers sockets passed down from parent under given label.

Usually used together with SystemD socket activation.
Expects exactly one FD, i.e. LISTEN_FDS must be set to 1.
LISTEN_PID is ignored, so is LISTEN_FDNAMES.
`)

	if err := set.Parse(args); errors.Is(err, flag.ErrHelp) {
		return nil
	} else if err != nil {
		return err
	}

	if set.NArg() != 1 {
		set.Usage()
		return fmt.Errorf("expected label but got %d arguments: %w", set.NArg(), errBadArg)
	}
	label := set.Arg(0)

	file, err := firstListenFd(e, label)
	if err != nil {
		return err
	}
	defer file.Close()

	dp, err := e.openDispatcher()
	if err != nil {
		return err
	}
	defer dp.Close()

	dst, created, err := dp.RegisterSocket(label, file)
	if err != nil {
		return fmt.Errorf("can't register fd: %w", err)
	}

	var inode uint64
	if fileInfo, err := file.Stat(); err == nil {
		if stat, ok := fileInfo.Sys().(*syscall.Stat_t); ok {
			inode = stat.Ino
		}
	}

	var msg string
	if created {
		msg = fmt.Sprintf("created destination %s", dst.String())
	} else {
		msg = fmt.Sprintf("updated destination %s", dst.String())
	}
	fmt.Fprintf(e.stdout, "registered socket ino:%d: %s\n", inode, msg)

	return nil
}

// Returns os.File for the first FD passed with systemd protocol for socket
// activation. Only LISTEN_FDS environment variable is taken into
// account. LISTEN_PID is ignored. LISTEN_FDNAMES are also ignored, name passed
// as an argument is used instead.  See sd_listen_fds(3) man-page for more info.
//
// It is considered an error not exactly one FD has been passed the process,
// i.e. LISTEN_FDS != 1.
func firstListenFd(e *env, name string) (*os.File, error) {
	// 1. Check LISTEN_FDS value
	listenFds := e.getenv("LISTEN_FDS")
	nfds, err := strconv.Atoi(listenFds)
	if err != nil {
		return nil, fmt.Errorf("can't parse LISTEN_FDS=%q: %w", listenFds, errBadArg)
	}
	if nfds != 1 {
		return nil, fmt.Errorf("expected LISTEN_FDS=1 but got %d: %w", nfds, errBadArg)
	}

	fd := listenFdsStart
	file := e.newFile(uintptr(fd), name)
	if file == nil {
		return nil, errBadFD // Can't happen on Linux if 0 <= fd <= MaxInt
	}

	return file, nil
}
