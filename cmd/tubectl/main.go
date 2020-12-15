// Program tubectl controls the behaviour of the socket dispatcher.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
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
	ctx            context.Context
	log            *log.Logger
	osFns
}

type osFns struct {
	// Override for os.Getenv
	getenv func(key string) string
	// Override for os.NewFile
	newFile func(fd uintptr, name string) *os.File
}

var (
	defaultEnv = env{
		stdout: os.Stdout,
		stderr: os.Stderr,
		ctx:    context.Background(),
		log:    log.New(log.Writer(), "", log.LstdFlags),
		osFns: osFns{
			getenv:  os.Getenv,
			newFile: os.NewFile,
		},
	}

	// Errors returned by tubectl
	errBadArg = syscall.EINVAL
	errBadFD  = syscall.EBADF
)

func (e *env) setupEnv() error {
	return rlimit.SetLockedMemoryLimits(e.memlimit)
}

func (e *env) createDispatcher() (*internal.Dispatcher, error) {
	if err := e.setupEnv(); err != nil {
		return nil, err
	}

	dp, err := internal.CreateDispatcher(e.netns, e.bpfFs)
	if err != nil {
		return nil, fmt.Errorf("can't load dispatcher: %w", err)
	}

	fmt.Fprintf(e.stdout, "created dispatcher in %v\n", dp.Path)
	return dp, nil
}

func (e *env) openDispatcher() (*internal.Dispatcher, error) {
	if err := e.setupEnv(); err != nil {
		return nil, err
	}

	dp, err := internal.OpenDispatcher(e.netns, e.bpfFs)
	if err != nil {
		return nil, fmt.Errorf("can't open dispatcher: %w", err)
	}

	fmt.Fprintf(e.stdout, "opened dispatcher at %v\n", dp.Path)
	return dp, nil
}

func (e *env) newFlagSet(name, usage string) *flag.FlagSet {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(e.stderr)
	set.Usage = func() {
		fmt.Fprintf(set.Output(), "Usage: tubectl %s %s\n", set.Name(), usage)
		set.PrintDefaults()
	}
	return set
}

type cmdFunc func(*env, ...string) error

func tubectl(e env, args []string) (err error) {
	defer func() {
		if err != nil {
			fmt.Fprintln(e.stderr, "Error:", err)
		}
	}()

	set := flag.NewFlagSet("tubectl", flag.ContinueOnError)
	set.SetOutput(e.stderr)
	set.StringVar(&e.netns, "netns", "/proc/self/ns/net", "`path` to the network namespace")
	set.StringVar(&e.bpfFs, "bpffs", "/sys/fs/bpf", "`path` to a BPF filesystem for state")
	set.Uint64Var(&e.memlimit, "memlimit", 100*1024*1024, "maximum locked memory in `bytes`")

	cmds := map[string]cmdFunc{
		"version":  version,
		"load":     load,
		"unload":   unload,
		"bind":     bind,
		"unbind":   unbind,
		"list":     list,
		"register": register,
		"serve":    serve,
	}

	set.Usage = func() {
		out := set.Output()
		fmt.Fprintf(out, "Usage: %s <flags> command <arguments and flags>\n\n", set.Name())

		fmt.Fprintln(out, "Available flags:")
		set.PrintDefaults()
		fmt.Fprintln(out)

		fmt.Fprintln(out, "Available commands:")
		for cmd := range cmds {
			fmt.Fprintln(out, "  "+cmd)
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
		cmd     = set.Arg(0)
		cmdArgs = set.Args()[1:]
		cmdFn   = cmds[cmd]
	)

	if cmdFn == nil {
		set.Usage()
		return fmt.Errorf("unknown command '%s'", cmd)
	}

	if err := cmdFn(&e, cmdArgs...); err != nil {
		return fmt.Errorf("%s: %w", cmd, err)
	}

	return nil
}

func main() {
	if err := tubectl(defaultEnv, os.Args[1:]); err != nil {
		os.Exit(1)
	}
}
