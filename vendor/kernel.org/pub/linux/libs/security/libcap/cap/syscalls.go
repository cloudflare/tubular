package cap

import (
	"syscall"

	"kernel.org/pub/linux/libs/security/libcap/psx"
)

// multisc provides syscalls overridable for testing purposes that
// support a single kernel security state for all OS threads.
// We use this version when we are cgo compiling because
// we need to manage the native C pthreads too.
var multisc = &syscaller{
	w3: psx.Syscall3,
	w6: psx.Syscall6,
	r3: syscall.RawSyscall,
	r6: syscall.RawSyscall6,
}

// singlesc provides a single threaded implementation. Users should
// take care to ensure the thread is locked and marked nogc.
var singlesc = &syscaller{
	w3: syscall.RawSyscall,
	w6: syscall.RawSyscall6,
	r3: syscall.RawSyscall,
	r6: syscall.RawSyscall6,
}
