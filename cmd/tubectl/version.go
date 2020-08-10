package main

import (
	"fmt"
	"runtime"
)

// Version is replaced by the Makefile.
var Version = "git"

func version(e env, args ...string) error {
	if len(args) > 0 {
		return fmt.Errorf("invalid arguments")
	}

	_, err := fmt.Fprintf(e.stdout, "tubectl version: %s (go runtime %s)\n", Version, runtime.Version())
	return err
}
