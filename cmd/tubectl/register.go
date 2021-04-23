package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"

	"code.cfops.it/sys/tubular/internal"
	"code.cfops.it/sys/tubular/internal/sysconn"
	"golang.org/x/sys/unix"
)

const (
	listenFdsStart = 3 // SD_LISTEN_FDS_START
)

func register(e *env, args ...string) error {
	set := e.newFlagSet("register", `<label>

Registers sockets passed down from parent under given label. Usually used
together with SystemD socket activation, as it expects the number of FDs in
LISTEN_FDS. LISTEN_PID is ignored, so is LISTEN_FDNAMES.

If multiple sockets are passed, the behaviour is as follows:
  - Only the first socket of each passed reuseport group is registered
  - Later (aka higher fd number) sockets overwrite lower ones
`)

	if err := set.Parse(args); err != nil {
		return err
	}

	if set.NArg() != 1 {
		set.Usage()
		return fmt.Errorf("expected label but got %d arguments: %w", set.NArg(), errBadArg)
	}
	label := set.Arg(0)

	files, err := listenFds(e, label)
	if err != nil {
		return err
	}
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()

	if len(files) == 0 {
		return fmt.Errorf("no sockets passed: %w", errBadArg)
	}

	conns := make([]syscall.Conn, 0, len(files))
	for _, file := range files {
		conns = append(conns, file)
	}

	conns, err = sysconn.Filter(conns, sysconn.FirstReuseport())
	if err != nil {
		return fmt.Errorf("filter reuseport: %w", err)
	}

	dp, err := e.openDispatcher(false)
	if err != nil {
		return err
	}
	defer dp.Close()

	registered := make(map[internal.Destination]bool)
	for _, conn := range conns {
		dst, created, err := dp.RegisterSocket(label, conn)
		if err != nil {
			return fmt.Errorf("register fd: %w", err)
		}

		if registered[*dst] {
			return fmt.Errorf("found multiple sockets for destination %s", dst)
		}
		registered[*dst] = true

		var msg string
		if created {
			msg = fmt.Sprintf("created destination %s", dst.String())
		} else {
			msg = fmt.Sprintf("updated destination %s", dst.String())
		}

		cookie, _ := socketCookie(conn)
		e.stdout.Logf("registered socket %s: %s\n", cookie, msg)
	}

	return nil
}

// Returns os.File for the first FD passed with systemd protocol for socket
// activation. Only LISTEN_FDS environment variable is taken into
// account. LISTEN_PID is ignored. LISTEN_FDNAMES are also ignored, name passed
// as an argument is used instead.  See sd_listen_fds(3) man-page for more info.
//
// It is considered an error not exactly one FD has been passed the process,
// i.e. LISTEN_FDS != 1.
func listenFds(e *env, name string) (res []*os.File, err error) {
	defer func() {
		if err == nil {
			return
		}

		for _, f := range res {
			f.Close()
		}
		res = nil
	}()

	// 1. Check LISTEN_FDS value
	listenFds := e.getenv("LISTEN_FDS")
	nfds, err := strconv.Atoi(listenFds)
	if err != nil {
		return nil, fmt.Errorf("parse LISTEN_FDS=%q: %w", listenFds, errBadArg)
	}

	for i := 0; i < nfds; i++ {
		file := e.newFile(uintptr(listenFdsStart+i), name)
		if file == nil {
			return nil, errBadFD // Can't happen on Linux if 0 <= fd <= MaxInt
		}

		res = append(res, file)
	}
	return res, nil
}

func socketCookie(conn syscall.Conn) (internal.SocketCookie, error) {
	var cookie uint64
	err := sysconn.Control(conn, func(fd int) (err error) {
		cookie, err = unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
		return
	})
	if err != nil {
		return 0, fmt.Errorf("getsockopt(SO_COOKIE): %v", err)
	}
	return internal.SocketCookie(cookie), nil
}
