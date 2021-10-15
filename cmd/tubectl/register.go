package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"syscall"

	"code.cfops.it/sys/tubular/internal"
	"code.cfops.it/sys/tubular/pkg/pidfd"
	"code.cfops.it/sys/tubular/pkg/sysconn"

	"golang.org/x/sys/unix"
	"inet.af/netaddr"
)

const (
	listenFdsStart = 3 // SD_LISTEN_FDS_START
)

func register(e *env, args ...string) error {
	set := e.newFlagSet("register", "label")
	set.Description = `
		Register sockets under the given label.

		Used together with systemd socket activation, it expects the
		number of sockets in LISTEN_FDS. LISTEN_PID and LISTEN_FDNAMES are
		ignored.

		Examples:
		  # Register all sockets passed from systemd under label foo
		  $ tubectl register foo`

	if err := set.Parse(args); err != nil {
		return err
	}

	// Use the current thread's netns, unit tests don't work well with
	// /proc/self/ns/net.
	targetNSPath := fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid())
	if err := namespacesEqual(e.netns, targetNSPath); err != nil {
		return err
	}

	label := set.Arg(0)

	files, err := listenFds(e, sysconn.FirstReuseport())
	if err != nil {
		return err
	}

	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()

	return registerFiles(e, label, files)
}

func registerPID(e *env, args ...string) error {
	set := e.newFlagSet("register-pid", "pid", "label", "protocol", "ip", "port")
	set.Description = `
		Register sockets from a process under the given label.

		The file descriptors of the target process will be enumerated to find
		matching sockets according to protocol, ip and port.

		Examples:
			# Register all supported sockets from the process with pid 12345
			$ tubectl register-pid 12345 foo tcp 127.0.0.1 80

			# Read the pid from a file
			$ tubectl register-pid /path/to.pid foo tcp 127.0.0.1 80`

	if err := set.Parse(args); err != nil {
		return err
	}

	pid, err := strconv.ParseInt(set.Arg(0), 10, 32)
	if err != nil {
		pidFile, pidErr := ioutil.ReadFile(set.Arg(0))
		if pidErr == nil {
			pid, err = strconv.ParseInt(strings.Trim(string(pidFile), "\r\n"), 10, 32)
		}
	}
	if err != nil {
		return fmt.Errorf("invalid pid %q: %s", set.Arg(0), err)
	}

	if err := namespacesEqual(e.netns, fmt.Sprintf("/proc/%d/ns/net", pid)); err != nil {
		return err
	}

	label := set.Arg(1)
	protocol := set.Arg(2)

	ip, err := netaddr.ParseIP(set.Arg(3))
	if err != nil {
		return fmt.Errorf("invalid IP %q: %s", set.Arg(3), err)
	}

	port, err := strconv.ParseUint(set.Arg(4), 10, 16)
	if err != nil {
		return fmt.Errorf("invalid port %q: %s", set.Arg(4), err)
	}

	filter := []sysconn.Predicate{
		sysconn.IgnoreENOTSOCK(sysconn.InetListener(protocol)),
		sysconn.LocalAddress(ip, int(port)),
		sysconn.FirstReuseport(),
	}

	files, err := pidfd.Files(int(pid), filter...)
	if err != nil {
		return fmt.Errorf("pid %d: %w", pid, err)
	}

	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()

	if err := registerFiles(e, label, files); err != nil {
		return fmt.Errorf("pid %d: %w", pid, err)
	}

	return nil
}

func registerFiles(e *env, label string, files []*os.File) error {
	if len(files) == 0 {
		return fmt.Errorf("no sockets: %w", errBadArg)
	}

	dp, err := e.openDispatcher(false)
	if err != nil {
		return err
	}
	defer dp.Close()

	registered := make(map[internal.Destination]bool)
	for _, file := range files {
		dst, created, err := dp.RegisterSocket(label, file)
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

		cookie, _ := socketCookie(file)
		e.stdout.Logf("registered socket %s: %s\n", cookie, msg)
	}

	return nil
}

// Returns os.File for the first FD passed with systemd protocol for socket
// activation. Only LISTEN_FDS environment variable is taken into
// account. LISTEN_PID is ignored. LISTEN_FDNAMES are also ignored, name passed
// as an argument is used instead.  See sd_listen_fds(3) man-page for more info.
func listenFds(e *env, p sysconn.Predicate) (res []*os.File, err error) {
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
		file := e.newFile(uintptr(listenFdsStart+i), "")
		if file == nil {
			return nil, errBadFD // Can't happen on Linux if 0 <= fd <= MaxInt
		}
		if keep, err := sysconn.FilterConn(file, p); err != nil {
			file.Close()
			return nil, err
		} else if !keep {
			file.Close()
			continue
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

func namespacesEqual(want, have string) error {
	var stat unix.Stat_t
	if err := unix.Stat(want, &stat); err != nil {
		return err
	}
	wantIno := stat.Ino

	if err := unix.Stat(have, &stat); err != nil {
		return err
	}
	haveIno := stat.Ino

	if wantIno != haveIno {
		return errors.New("can't register sockets from different network namespace")
	}

	return nil
}
