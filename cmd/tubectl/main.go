// Program tubectl controls the behaviour of the socket dispatcher.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"code.cfops.it/sys/tubular/internal/rlimit"
)

type env struct {
	stdout, stderr io.Writer
	netns          string
	bpfFs          string
	memlimit       uint64
}

func (e *env) adjustMemlimit() error {
	return rlimit.SetLockedMemoryLimits(e.memlimit)
}

type cmdFunc func(env, ...string) error

func tubectl(stdout, stderr io.Writer, args ...string) error {
	e := env{
		stdout: stdout,
		stderr: stderr,
	}

	set := flag.NewFlagSet("tubectl", flag.ContinueOnError)
	set.StringVar(&e.netns, "netns", "/proc/self/ns/net", "`path` to the network namespace")
	set.StringVar(&e.bpfFs, "bpffs", "/sys/fs/bpf", "`path` to a BPF filesystem for state")
	set.Uint64Var(&e.memlimit, "memlimit", 10*1024*1024, "maximum locked memory in `bytes`")

	cmds := map[string]cmdFunc{
		"version": version,
		"load":    load,
		"unload":  unload,
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

	if err := set.Parse(args); err != nil {
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

	if err := cmdFn(e, cmdArgs...); err != nil {
		return fmt.Errorf("%s: %s", cmd, err)
	}

	return nil
}

func main() {
	if err := tubectl(os.Stdout, os.Stderr, os.Args[1:]...); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
