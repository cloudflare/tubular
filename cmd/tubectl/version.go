package main

import (
	"runtime"
)

// Version is replaced by the Makefile.
var Version = "git"

func version(e *env, args ...string) error {
	set := e.newFlagSet("version")
	set.Description = "Show version information."
	if err := set.Parse(args); err != nil {
		return err
	}

	e.stdout.Logf("tubectl version: %s (go runtime %s)\n", Version, runtime.Version())
	return nil
}
