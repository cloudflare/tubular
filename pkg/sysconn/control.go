package sysconn

import (
	"fmt"
	"syscall"
)

// Control invokes conn.SyscallConn().Control.
func Control(conn syscall.Conn, fn func(int) error) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("SyscallConn: %w", err)
	}

	var fnErr error
	err = raw.Control(func(fd uintptr) {
		fnErr = fn(int(fd))
	})
	if err != nil {
		return fmt.Errorf("Control: %w", err)
	}
	return fnErr
}

// ControlInt invokes conn.SyscallConn().Control and returns an integer.
func ControlInt(conn syscall.Conn, fn func(int) (int, error)) (int, error) {
	var value int
	return value, Control(conn, func(fd int) (err error) {
		value, err = fn(fd)
		return
	})
}
