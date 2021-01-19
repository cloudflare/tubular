package cap

import (
	"errors"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

// Launcher holds a configuration for launching a child process with
// capability state different from (generally more restricted than)
// the parent.
//
// Note, go1.10 is the earliest version of the Go toolchain that can
// support this abstraction.
type Launcher struct {
	path string
	args []string
	env  []string

	callbackFn func(pa *syscall.ProcAttr, data interface{}) error

	changeUIDs bool
	uid        int

	changeGIDs bool
	gid        int
	groups     []int

	changeMode bool
	mode       Mode

	iab *IAB

	chroot string
}

// NewLauncher returns a new launcher for the specified program path
// and args with the specified environment.
func NewLauncher(path string, args []string, env []string) *Launcher {
	return &Launcher{
		path: path,
		args: args,
		env:  env,
	}
}

// Callback specifies a callback for Launch() to call before changing
// privilege. The only thing that is assumed is that the OS thread in
// use to call this callback function at launch time will be the one
// that ultimately calls fork. Any returned error value of said
// function will terminate the launch process. A nil callback (the
// default) is ignored. The specified callback fn should not call any
// "cap" package functions since this may deadlock or generate
// undefined behavior for the parent process.
func (attr *Launcher) Callback(fn func(*syscall.ProcAttr, interface{}) error) {
	attr.callbackFn = fn
}

// SetUID specifies the UID to be used by the launched command.
func (attr *Launcher) SetUID(uid int) {
	attr.changeUIDs = true
	attr.uid = uid
}

// SetGroups specifies the GID and supplementary groups for the
// launched command.
func (attr *Launcher) SetGroups(gid int, groups []int) {
	attr.changeGIDs = true
	attr.gid = gid
	attr.groups = groups
}

// SetMode specifies the libcap Mode to be used by the launched command.
func (attr *Launcher) SetMode(mode Mode) {
	attr.changeMode = true
	attr.mode = mode
}

// SetIAB specifies the AIB capability vectors to be inherited by the
// launched command. A nil value means the prevailing vectors of the
// parent will be inherited.
func (attr *Launcher) SetIAB(iab *IAB) {
	attr.iab = iab
}

// SetChroot specifies the chroot value to be used by the launched
// command. An empty value means no-change from the prevailing value.
func (attr *Launcher) SetChroot(root string) {
	attr.chroot = root
}

// lResult is used to get the result from the doomed launcher thread.
type lResult struct {
	pid int
	err error
}

// ErrLaunchFailed is returned if a launch was aborted with no more
// specific error.
var ErrLaunchFailed = errors.New("launch failed")

// ErrNoLaunch indicates the go runtime available to this binary does
// not reliably support launching. See cap.LaunchSupported.
var ErrNoLaunch = errors.New("launch not supported")

// ErrAmbiguousChroot indicates that the Launcher is being used in
// addition to callback supplied Chroot. The former should be used
// exclusively for this.
var ErrAmbiguousChroot = errors.New("use Launcher for chroot")

// ErrAmbiguousIDs indicates that the Launcher is being used in
// addition to callback supplied Credentials. The former should be
// used exclusively for this.
var ErrAmbiguousIDs = errors.New("use Launcher for uids and gids")

// ErrAmbiguousAmbient indicates that the Launcher is being used in
// addition callback supplied ambient set and the former should be
// used exclusively in a Launch call.
var ErrAmbiguousAmbient = errors.New("use Launcher for ambient caps")

// lName is the name we temporarily give to the launcher thread. Note,
// this will likely stick around in the process tree if the Go runtime
// is not cleaning up locked launcher OS threads.
var lName = []byte("cap-launcher\000")

// <uapi/linux/prctl.h>
const prSetName = 15

//go:uintptrescapes
func launch(result chan<- lResult, attr *Launcher, data interface{}, quit chan<- struct{}) {
	if quit != nil {
		defer close(quit)
	}

	pid := syscall.Getpid()
	// Wait until we are not scheduled on the parent thread.  We
	// will exit this thread once the child has launched, and
	// don't want other goroutines to use this thread afterwards.
	runtime.LockOSThread()
	tid := syscall.Gettid()
	if tid == pid {
		// Force the go runtime to find a new thread to run on.
		quit := make(chan struct{})
		go launch(result, attr, data, quit)

		// Wait for that go routine to complete.
		<-quit
		runtime.UnlockOSThread()
		return
	}

	// By never releasing the LockOSThread here, we guarantee that
	// the runtime will terminate the current OS thread once this
	// function returns.

	// Name the launcher thread - transient, but helps to debug if
	// the callbackFn or something else hangs up.
	singlesc.prctlrcall(prSetName, uintptr(unsafe.Pointer(&lName[0])), 0)

	// Provide a way to serialize the caller on the thread
	// completing.
	defer close(result)

	pa := &syscall.ProcAttr{
		Files: []uintptr{0, 1, 2},
	}
	var err error
	var needChroot bool

	if len(attr.env) != 0 {
		pa.Env = attr.env
	} else {
		pa.Env = os.Environ()
	}

	if attr.callbackFn != nil {
		if err = attr.callbackFn(pa, data); err != nil {
			goto abort
		}
	}

	if needChroot, err = validatePA(pa, attr.chroot); err != nil {
		goto abort
	}
	if attr.changeUIDs {
		if err = singlesc.setUID(attr.uid); err != nil {
			goto abort
		}
	}
	if attr.changeGIDs {
		if err = singlesc.setGroups(attr.gid, attr.groups); err != nil {
			goto abort
		}
	}
	if attr.changeMode {
		if err = singlesc.setMode(attr.mode); err != nil {
			goto abort
		}
	}
	if attr.iab != nil {
		if err = singlesc.iabSetProc(attr.iab); err != nil {
			goto abort
		}
	}

	if needChroot {
		c := GetProc()
		if err = c.SetFlag(Effective, true, SYS_CHROOT); err != nil {
			goto abort
		}
		if err = singlesc.setProc(c); err != nil {
			goto abort
		}
	}
	pid, err = syscall.ForkExec(attr.path, attr.args, pa)

abort:
	if err != nil {
		pid = -1
	}
	result <- lResult{pid: pid, err: err}
}

// Launch performs a new program launch with security state specified
// in the supplied attr settings.
func (attr *Launcher) Launch(data interface{}) (int, error) {
	if attr.path == "" || len(attr.args) == 0 {
		return -1, ErrLaunchFailed
	}
	if !LaunchSupported {
		return -1, ErrNoLaunch
	}

	scwMu.Lock()
	defer scwMu.Unlock()
	result := make(chan lResult)

	go launch(result, attr, data, nil)
	for {
		select {
		case v, ok := <-result:
			if !ok {
				return -1, ErrLaunchFailed
			}
			return v.pid, v.err
		default:
			runtime.Gosched()
		}
	}
}
