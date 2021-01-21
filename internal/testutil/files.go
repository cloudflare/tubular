package testutil

import (
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// FileStatusFlags returns flags for the open file description onderlying conn.
func FileStatusFlags(tb testing.TB, conn syscall.Conn) (flags int) {
	tb.Helper()

	raw, err := conn.SyscallConn()
	if err != nil {
		tb.Fatal(err)
	}

	err = raw.Control(func(fd uintptr) {
		flags, err = unix.FcntlInt(fd, unix.F_GETFL, 0)
		if err != nil {
			tb.Fatal("fcntl(F_GETFL):", err)
		}
	})
	if err != nil {
		tb.Fatal("Control:", err)
	}

	return
}
