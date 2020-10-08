// Program tubectl controls the behaviour of the socket dispatcher.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"syscall"

	"code.cfops.it/sys/tubular/internal"
	"code.cfops.it/sys/tubular/internal/rlimit"
)

type env struct {
	stdout, stderr io.Writer
	netns          string
	bpfFs          string
	memlimit       uint64
}

var (
	// Errors returned by tubectl
	errBadArg = syscall.EINVAL
)

func (e *env) adjustMemlimit() error {
	return rlimit.SetLockedMemoryLimits(e.memlimit)
}

func (e *env) openDispatcher() (*internal.Dispatcher, error) {
	if err := e.adjustMemlimit(); err != nil {
		return nil, err
	}

	dp, err := internal.OpenDispatcher(e.netns, e.bpfFs)
	if err != nil {
		return nil, fmt.Errorf("can't open dispatcher: %w", err)
	}

	return dp, nil
}

func (e *env) newFlagSet(name string) *flag.FlagSet {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(e.stderr)
	return set
}

type cmdFunc func(*env, ...string) error

func tubectl(stdout, stderr io.Writer, args []string) (err error) {
	defer func() {
		if err != nil {
			fmt.Fprintln(stderr, "Error:", err)
		}
	}()

	e := env{
		stdout: stdout,
		stderr: stderr,
	}

	set := e.newFlagSet("tubectl")
	set.StringVar(&e.netns, "netns", "/proc/self/ns/net", "`path` to the network namespace")
	set.StringVar(&e.bpfFs, "bpffs", "/sys/fs/bpf", "`path` to a BPF filesystem for state")
	set.Uint64Var(&e.memlimit, "memlimit", 10*1024*1024, "maximum locked memory in `bytes`")

	cmds := map[string]cmdFunc{
		"version":  version,
		"load":     load,
		"unload":   unload,
		"bind":     bind,
		"unbind":   unbind,
		"list":     list,
		"register": register,
	}

	set.Usage = func() {
		fmt.Fprintf(stderr, "Usage: %s [flags] command [arguments and flags]\n\n", set.Name())

		fmt.Fprintln(stderr, "Available flags:")
		set.PrintDefaults()
		fmt.Fprintln(stderr)

		fmt.Fprintln(stderr, "Available commands:")
		for cmd := range cmds {
			fmt.Fprintln(stderr, "  "+cmd)
		}
		fmt.Fprintln(stderr)
	}

	if err = set.Parse(args); err != nil {
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
		cmd     = set.Arg(0)
		cmdArgs = set.Args()[1:]
		cmdFn   = cmds[cmd]
	)

	if cmdFn == nil {
		set.Usage()
		return fmt.Errorf("unknown command '%s'", cmd)
	}

	if err := cmdFn(&e, cmdArgs...); err != nil {
		return fmt.Errorf("%s: %s", cmd, err)
	}

	return nil
}

func main() {
	if err := tubectl(os.Stdout, os.Stderr, os.Args[1:]); err != nil {
		os.Exit(1)
	}
}
