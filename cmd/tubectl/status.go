package main

import (
	"fmt"
	"text/tabwriter"
)

func list(e env, args ...string) error {
	if len(args) > 0 {
		return fmt.Errorf("invalid arguments")
	}

	dp, err := e.openDispatcher()
	if err != nil {
		return err
	}
	defer dp.Close()

	bindings, err := dp.Bindings()
	if err != nil {
		return fmt.Errorf("can't get bindings: %s", err)
	}

	w := tabwriter.NewWriter(e.stdout, 0, 0, 1, ' ', tabwriter.AlignRight)
	fmt.Fprintln(e.stdout, "Bindings:")
	fmt.Fprintln(w, "label\tprotocol\tprefix\tport\t")

	for _, bind := range bindings {
		_, err := fmt.Fprintf(w, "%s\t%v\t%s\t%d\t\n", bind.Label, bind.Protocol, bind.Prefix, bind.Port)
		if err != nil {
			return err
		}
	}

	if err := w.Flush(); err != nil {
		return err
	}

	return nil
}
