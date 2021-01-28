package main

import (
	"errors"
	"flag"
	"fmt"
	"runtime"
)

// Version is replaced by the Makefile.
var Version = "git"

func version(e *env, args ...string) error {
	set := e.newFlagSet("version", `

Show version information.
`)
	if err := set.Parse(args); errors.Is(err, flag.ErrHelp) {
		return nil
	} else if err != nil {
		return err
	}

	if set.NArg() > 0 {
		return fmt.Errorf("invalid arguments")
	}

	e.stdout.Logf("tubectl version: %s (go runtime %s)\n", Version, runtime.Version())
	return nil
}
