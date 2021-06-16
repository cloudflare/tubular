package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"text/tabwriter"
	"time"

	"code.cfops.it/sys/tubular/internal"
	"code.cfops.it/sys/tubular/internal/reachable"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/unix"
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
	set := e.newFlagSet("metrics", "address", "port", "--", "bindings-file")
	set.Description = `
		Expose metrics in prometheus export format.
		Given a bindings file, will also perform reachability checks.

		Examples:
		  $ tubectl metrics 127.0.0.1 8000
		  OR
		  $ tubectl metrics 127.0.0.1 8000 /etc/tubular/bindings.json
		  THEN
		  $ curl http://127.0.0.1:8000/metrics`

	timeout := set.Duration("timeout", 30*time.Second, "Duration to wait for an HTTP metrics request to complete.")
	if err := set.Parse(args); err != nil {
		return err
	}

	address := set.Arg(0)
	port := set.Arg(1)
	bindingsPath := set.Arg(2)

	if err := e.setupEnv(); err != nil {
		return err
	}

	var bindings internal.Bindings
	if bindingsPath != "" {
		// If the netns that we are currently being executed in is not the
		// same as the one provided through the command args, then exit.
		// We don't support collecting metrics in a different netns right
		// now.
		targetNSPath := fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid())
		if err := namespacesEqual(e.netns, targetNSPath); err != nil {
			return err
		}

		b, err := loadConfig(bindingsPath)
		if err != nil {
			return err
		}
		bindings = b
	}

	// Create an instance of the prometheus registry and register all collectors.
	reg, err := tubularRegistry(e, bindings)
	if err != nil {
		return err
	}

	// Create TCP listener used for metrics endpoint.
	ln, err := e.listen("tcp", fmt.Sprintf("%s:%s", address, port))
	if err != nil {
		return err
	}
	defer ln.Close()

	e.stdout.Log("Listening on", ln.Addr().String())

	// Create an instance of the metrics server
	srv := metricsServer(e.ctx, reg, timeout)

	// Close the http server when the env context is closed.
	go func() {
		<-e.ctx.Done()
		srv.Close()
	}()

	// Block on serving the metrics http server.
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve http: %s", err)
	}

	return nil
}

func tubularRegistry(e *env, b internal.Bindings) (*prometheus.Registry, error) {
	reg := prometheus.NewRegistry()
	tubularReg := prometheus.WrapRegistererWithPrefix("tubular_", reg)

	coll := internal.NewCollector(e.stderr, e.netns, e.bpfFs)
	if err := tubularReg.Register(coll); err != nil {
		return nil, fmt.Errorf("register collector: %s", err)
	}

	if b != nil {
		reach := reachable.NewReachable(e.stderr, b)
		if err := tubularReg.Register(reach); err != nil {
			return nil, fmt.Errorf("register reachability collector: %s", err)
		}
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
		return nil, fmt.Errorf("register build info: %s", err)
	}
	return reg, nil
}

func metricsServer(ctx context.Context, reg *prometheus.Registry, t *time.Duration) http.Server {
	handler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		ErrorHandling:       promhttp.HTTPErrorOnError,
		MaxRequestsInFlight: 1,
		Timeout:             *t,
	})

	return http.Server{
		Handler:     handler,
		ReadTimeout: *t,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
}
