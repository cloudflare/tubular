package main

import (
	"fmt"
)

const usageMsg = `Usage: %s <label>

Registers sockets passed down from parent under given label.
Usually used together with SystemD socket activation.

`

func register(e env, args ...string) error {
	set := e.newFlagSet("register")
	set.Usage = func() {
		fmt.Fprintf(set.Output(), usageMsg, set.Name())
		set.PrintDefaults()
	}
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 1 {
		set.Usage()
		return fmt.Errorf("missing arguments")
	}

	// FIXME: Finish me
	return fmt.Errorf("NYI")
}
