package main

import (
	"errors"

	"github.com/cloudflare/tubular/internal"
)

func load(e *env, args ...string) error {
	set := e.newFlagSet("load")
	set.Description = "Load the tubular dispatcher."
	if err := set.Parse(args); err != nil {
		return err
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
	set := e.newFlagSet("unload")
	set.Description = "Unload the tubular dispatcher, removing any present state."
	if err := set.Parse(args); err != nil {
		return err
	}

	err := internal.UnloadDispatcher(e.netns, e.bpfFs)
	if errors.Is(err, internal.ErrNotLoaded) {
		e.stderr.Log("dispatcher is not loaded in", e.netns)
		return nil
	} else if err != nil {
		return err
	}

	e.stdout.Logf("unloaded dispatcher from %s\n", e.netns)
	return nil
}

func upgrade(e *env, args ...string) error {
	set := e.newFlagSet("upgrade")
	set.Description = "Upgrade the tubular dispatcher, while preserving present state."
	if err := set.Parse(args); err != nil {
		return err
	}

	if err := e.setupEnv(); err != nil {
		return err
	}

	id, err := internal.UpgradeDispatcher(e.netns, e.bpfFs)
	if err != nil {
		return err
	}

	e.stdout.Logf("Upgraded dispatcher to %s, program ID #%d", Version, id)
	return nil
}
