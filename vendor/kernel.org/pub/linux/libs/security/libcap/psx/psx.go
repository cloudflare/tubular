// +build linux,!cgo
// +build go1.16 allthreadssyscall

package psx // import "kernel.org/pub/linux/libs/security/libcap/psx"

import (
	"syscall"
)

var (
	Syscall3 = syscall.AllThreadsSyscall
	Syscall6 = syscall.AllThreadsSyscall6
)
