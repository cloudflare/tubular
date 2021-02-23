package main

import (
	"errors"
	"flag"
	"fmt"
	"sort"
	"text/tabwriter"

	"code.cfops.it/sys/tubular/internal"
)

func list(e *env, args ...string) error {
	set := e.newFlagSet("list", `

Show current bindings and destinations.
`)
	if err := set.Parse(args); errors.Is(err, flag.ErrHelp) {
		return nil
	} else if err != nil {
		return err
	}

	if set.NArg() > 0 {
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

	// Output from most specific to least specific.
	sort.Sort(bindings)

	w := tabwriter.NewWriter(e.stdout, 0, 0, 1, ' ', tabwriter.AlignRight)
	e.stdout.Log("Bindings:")
	fmt.Fprintln(w, "protocol\tprefix\tport\tlabel\t")

	for _, bind := range bindings {
		_, err := fmt.Fprintf(w, "%v\t%s\t%d\t%s\t\n", bind.Protocol, bind.Prefix, bind.Port, bind.Label)
		if err != nil {
			return err
		}
	}

	if err := w.Flush(); err != nil {
		return err
	}

	metrics, err := dp.Metrics()
	if err != nil {
		return fmt.Errorf("get metrics: %s", err)
	}

	dests := make([]internal.Destination, 0, len(metrics.Destinations))
	for dest := range metrics.Destinations {
		dests = append(dests, dest)
	}

	sortDestinations(dests)

	e.stdout.Log("\nDestinations:")
	fmt.Fprintln(w, "label\tdomain\tprotocol\tsocket\tlookups\tmisses\terrors\t")

	for _, dest := range dests {
		destMetrics := metrics.Destinations[dest]
		_, err := fmt.Fprint(w,
			dest.Label, "\t",
			dest.Domain, "\t",
			dest.Protocol, "\t",
			dest.Socket, "\t",
			destMetrics.Lookups, "\t",
			destMetrics.Misses, "\t",
			destMetrics.TotalErrors(), "\t",
			"\n",
		)
		if err != nil {
			return err
		}
	}

	if err := w.Flush(); err != nil {
		return err
	}

	return nil
}

func sortDestinations(dests []internal.Destination) {
	sort.Slice(dests, func(i, j int) bool {
		a, b := dests[i], dests[j]
		if a.Label != b.Label {
			return a.Label < b.Label
		}

		if a.Domain != b.Domain {
			return a.Domain < b.Domain
		}

		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}

		return a.Socket < b.Socket
	})
}
