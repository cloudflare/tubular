package main

import (
	"errors"
	"fmt"

	"code.cfops.it/sys/tubular/internal"
)

func load(e *env, args ...string) error {
	if len(args) > 0 {
		return fmt.Errorf("invalid arguments")
	}

	dp, err := e.createDispatcher()
	if errors.Is(err, internal.ErrLoaded) {
		fmt.Fprintln(e.stderr, "dispatcher is already loaded in", e.netns)
		return nil
	} else if err != nil {
		return err
	}
	defer dp.Close()

	fmt.Fprintf(e.stdout, "loaded dispatcher into %s\n", e.netns)
	return nil
}

func unload(e *env, args ...string) error {
	if len(args) > 0 {
		return fmt.Errorf("invalid arguments")
	}

	dp, err := e.openDispatcher()
	if errors.Is(err, internal.ErrNotLoaded) {
		fmt.Fprintln(e.stderr, "dispatcher is not loaded in", e.netns)
		return nil
	} else if err != nil {
		return err
	}

	if err := dp.Unload(); err != nil {
		return err
	}

	fmt.Fprintf(e.stdout, "unloaded dispatcher from %s\n", e.netns)
	return nil
}
