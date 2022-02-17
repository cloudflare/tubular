// Program tubectl controls the behaviour of the socket dispatcher.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/cloudflare/tubular/internal"
	"github.com/cloudflare/tubular/internal/log"
	"github.com/cloudflare/tubular/internal/rlimit"

	"golang.org/x/sys/unix"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

type env struct {
	stdout, stderr log.Logger
	netns          string
	bpfFs          string
	ctx            context.Context
	// Override for os.Getenv
	getenv func(key string) string
	// Override for os.NewFile
	newFile func(fd uintptr, name string) *os.File
	// Override for net.Listen
	listen func(network, addr string) (net.Listener, error)
}

var (
	defaultEnv = env{
		stdout:  log.NewStdLogger(os.Stdout),
		stderr:  log.NewStdLogger(os.Stderr),
		ctx:     context.Background(),
		getenv:  os.Getenv,
		newFile: os.NewFile,
		listen:  net.Listen,
	}

	// Errors returned by tubectl
	errBadArg = syscall.EINVAL
	errBadFD  = syscall.EBADF
)

func (e *env) setupEnv() error {
	haveSysResource, err := cap.GetProc().GetFlag(cap.Effective, cap.SYS_RESOURCE)
	if err != nil {
		return fmt.Errorf("get capabilities: %s", err)
	}

	if haveSysResource {
		// Raise the memlock rlimit to unlimited when invoked via sudo.
		err = rlimit.SetLockedMemoryLimits(unix.RLIM_INFINITY)
		if err != nil {
			return fmt.Errorf("set RLIMIT_MEMLOCK: %s", err)
		}
	}

	return nil
}

func (e *env) createDispatcher() (*internal.Dispatcher, error) {
	if err := e.setupEnv(); err != nil {
		return nil, err
	}

	dp, err := internal.CreateDispatcher(e.netns, e.bpfFs)
	if err != nil {
		return nil, fmt.Errorf("can't load dispatcher: %w", err)
	}

	e.stdout.Logf("created dispatcher in %v\n", dp.Path)
	return dp, nil
}

func (e *env) openDispatcher(readOnly bool) (*internal.Dispatcher, error) {
	if err := e.setupEnv(); err != nil {
		return nil, err
	}

	dp, err := internal.OpenDispatcher(e.netns, e.bpfFs, readOnly)
	if err != nil {
		return nil, fmt.Errorf("can't open dispatcher: %w", err)
	}

	e.stdout.Logf("opened dispatcher at %v\n", dp.Path)
	return dp, nil
}

func (e *env) newFlagSet(name string, args ...string) *flagSet {
	return newFlagSet(e.stderr, name, args...)
}

var cmds = []struct {
	name   string
	fn     func(*env, ...string) error
	hidden bool
}{
	// Noun commands should not make any changes to state.
	// Verb commands should make changes to state.
	{"version", version, false},
	// Dispatcher lifecycle.
	{"status", status, false},
	{"metrics", metrics, false},
	{"load", load, false},
	{"unload", unload, false},
	{"upgrade", upgrade, false},
	// Bindings
	{"bindings", bindings, false},
	{"bind", bind, false},
	{"unbind", unbind, false},
	{"load-bindings", loadBindings, false},
	// Destinations
	{"register", register, false},
	{"register-pid", registerPID, false},
	{"unregister", unregister, false},
	// Deprecated
	{"list", list, true},
}

func tubectl(e env, args []string) (err error) {
	defer func() {
		if err != nil {
			e.stderr.Log("Error:", err)
		}
	}()

	set := flag.NewFlagSet("tubectl", flag.ContinueOnError)
	set.SetOutput(e.stderr)
	set.StringVar(&e.netns, "netns", "/proc/self/ns/net", "`path` to the network namespace")
	set.StringVar(&e.bpfFs, "bpffs", "/sys/fs/bpf", "`path` to a BPF filesystem for state")

	set.Usage = func() {
		out := set.Output()
		fmt.Fprintf(out, "Usage: %s <flags> command <arguments and flags>\n\n", set.Name())

		fmt.Fprintln(out, "Available flags:")
		set.PrintDefaults()
		fmt.Fprintln(out)

		fmt.Fprintln(out, "Available commands (use <command> -h for help):")
		for _, cmd := range cmds {
			if cmd.hidden {
				continue
			}
			fmt.Fprintln(out, "  "+cmd.name)
		}
		fmt.Fprintln(out)
	}

	if err := set.Parse(args); errors.Is(err, flag.ErrHelp) {
		return nil
	} else if err != nil {
		return err
	}

	if e.netns == "" {
		return fmt.Errorf("invalid -netns flag")
	}

	if e.bpfFs == "" {
		return fmt.Errorf("invalid -bpffs flag")
	}

	if set.NArg() < 1 {
		set.Usage()
		return fmt.Errorf("missing command")
	}

	var (
		cmdName = set.Arg(0)
		cmdArgs = set.Args()[1:]
	)

	for _, cmd := range cmds {
		if cmd.name != cmdName {
			continue
		}

		err := cmd.fn(&e, cmdArgs...)
		if err != nil && !errors.Is(err, flag.ErrHelp) {
			return fmt.Errorf("%s: %w", cmdName, err)
		}

		return nil
	}

	set.Usage()
	return fmt.Errorf("unknown command '%s'", cmdName)
}

func main() {
	if err := tubectl(defaultEnv, os.Args[1:]); err != nil {
		os.Exit(1)
	}
}
