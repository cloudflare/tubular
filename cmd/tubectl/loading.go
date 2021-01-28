package main

import (
	"errors"
	"flag"
	"fmt"

	"code.cfops.it/sys/tubular/internal"
)

func load(e *env, args ...string) error {
	set := e.newFlagSet("load", `

Load the tubular dispatcher.
`)
	if err := set.Parse(args); errors.Is(err, flag.ErrHelp) {
		return nil
	} else if err != nil {
		return err
	}

	if flag.NArg() > 0 {
		return fmt.Errorf("invalid arguments")
	}

	dp, err := e.createDispatcher()
	if errors.Is(err, internal.ErrLoaded) {
		e.stderr.Log("dispatcher is already loaded in", e.netns)
		return nil
	} else if err != nil {
		return err
	}
	defer dp.Close()

	e.stdout.Logf("loaded dispatcher into %s\n", e.netns)
	return nil
}

func unload(e *env, args ...string) error {
	set := e.newFlagSet("unload", `

Unload the tubular dispatcher, removing any present state.
`)
	if err := set.Parse(args); errors.Is(err, flag.ErrHelp) {
		return nil
	} else if err != nil {
		return err
	}

	if flag.NArg() > 0 {
		return fmt.Errorf("invalid arguments")
	}

	dp, err := e.openDispatcher()
	if errors.Is(err, internal.ErrNotLoaded) {
		e.stderr.Log("dispatcher is not loaded in", e.netns)
		return nil
	} else if err != nil {
		return err
	}

	if err := dp.Unload(); err != nil {
		return err
	}

	e.stdout.Logf("unloaded dispatcher from %s\n", e.netns)
	return nil
}
