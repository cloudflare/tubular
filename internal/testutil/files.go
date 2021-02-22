package testutil

import (
	"syscall"
	"testing"

	"code.cfops.it/sys/tubular/internal/sysconn"
	"golang.org/x/sys/unix"
)

// FileStatusFlags returns flags for the open file description onderlying conn.
func FileStatusFlags(tb testing.TB, conn syscall.Conn) int {
	tb.Helper()

	flags, err := sysconn.ControlInt(conn, func(fd int) (int, error) {
		return unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	})
	if err != nil {
		tb.Fatal("fcntl(F_GETFL):", err)
	}

	return flags
}
