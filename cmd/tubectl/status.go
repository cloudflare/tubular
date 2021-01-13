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

	metrics, err := dp.Metrics()
	if err != nil {
		return fmt.Errorf("get metrics: %s", err)
	}

	dests := make([]internal.Destination, 0, len(metrics.Destinations))
	for dest := range metrics.Destinations {
		dests = append(dests, dest)
	}

	sortDestinations(dests)

	fmt.Fprintln(e.stdout, "\nDestinations:")
	fmt.Fprintln(w, "label\tdomain\tprotocol\tsocket\tpackets\tdropped\t")

	for _, dest := range dests {
		destMestrics := metrics.Destinations[dest]
		dropped := destMestrics.DroppedPacketsIncompatibleSocket + destMestrics.DroppedPacketsMissingSocket
		_, err := fmt.Fprint(w,
			dest.Label, "\t",
			dest.Domain, "\t",
			dest.Protocol, "\t",
			dest.Socket, "\t",
			destMestrics.ReceivedPackets, "\t",
			dropped, "\t",
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
