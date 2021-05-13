package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"sort"
	"text/tabwriter"
	"time"

	"code.cfops.it/sys/tubular/internal"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func list(e *env, args ...string) error {
	set := e.newFlagSet("list", "--", "label")
	set.Description = "Show current bindings and destinations."
	if err := set.Parse(args); err != nil {
		return err
	}

	dp, err := e.openDispatcher(true)
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

	label := set.Arg(0)

	w := tabwriter.NewWriter(e.stdout, 0, 0, 1, ' ', tabwriter.AlignRight)
	e.stdout.Log("Bindings:")
	fmt.Fprintln(w, "protocol\tprefix\tport\tlabel\t")

	for _, bind := range bindings {
		if label != "" && bind.Label != label {
			continue
		}

		_, err := fmt.Fprintf(w, "%v\t%s\t%d\t%s\t\n", bind.Protocol, bind.Prefix, bind.Port, bind.Label)
		if err != nil {
			return err
		}
	}

	if err := w.Flush(); err != nil {
		return err
	}

	dests, cookies, err := dp.Destinations()
	if err != nil {
		return fmt.Errorf("get destinations: %s", err)
	}

	sortDestinations(dests)

	metrics, err := dp.Metrics()
	if err != nil {
		return fmt.Errorf("get metrics: %s", err)
	}

	e.stdout.Log("\nDestinations:")
	fmt.Fprintln(w, "label\tdomain\tprotocol\tsocket\tlookups\tmisses\terrors\t")

	for _, dest := range dests {
		if label != "" && dest.Label != label {
			continue
		}

		destMetrics := metrics.Destinations[dest]
		_, err := fmt.Fprint(w,
			dest.Label, "\t",
			dest.Domain, "\t",
			dest.Protocol, "\t",
			cookies[dest], "\t",
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

		return a.Protocol < b.Protocol
	})
}

func metrics(e *env, args ...string) error {
	set := e.newFlagSet("metrics", "address", "port")
	set.Description = `
		Expose metrics in prometheus export format.

		Examples:
		  $ tubectl metrics 127.0.0.1 8000
		  $ curl http://127.0.0.1:8000/metrics`

	timeout := set.Duration("timeout", 30*time.Second, "Duration to wait for an HTTP metrics request to complete.")
	if err := set.Parse(args); err != nil {
		return err
	}

	address := set.Arg(0)
	port := set.Arg(1)

	if err := e.setupEnv(); err != nil {
		return err
	}

	reg := prometheus.NewRegistry()
	tubularReg := prometheus.WrapRegistererWithPrefix("tubular_", reg)
	coll := internal.NewCollector(e.stderr, e.netns, e.bpfFs)
	if err := tubularReg.Register(coll); err != nil {
		return fmt.Errorf("register collector: %s", err)
	}

	buildInfo := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "build_info",
		Help: "Build and version information",
		ConstLabels: prometheus.Labels{
			"goversion": runtime.Version(),
			"version":   Version,
		},
	})
	buildInfo.Set(1)
	if err := reg.Register(buildInfo); err != nil {
		return fmt.Errorf("register build info: %s", err)
	}

	ln, err := e.listen("tcp", fmt.Sprintf("%s:%s", address, port))
	if err != nil {
		return err
	}
	defer ln.Close()

	e.stdout.Log("Listening on", ln.Addr().String())

	handler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		ErrorHandling:       promhttp.HTTPErrorOnError,
		MaxRequestsInFlight: 1,
		Timeout:             *timeout,
	})

	srv := http.Server{
		Handler:     handler,
		ReadTimeout: *timeout,
		BaseContext: func(net.Listener) context.Context { return e.ctx },
	}

	go func() {
		<-e.ctx.Done()
		srv.Close()
	}()

	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve http: %s", err)
	}

	return nil
}
