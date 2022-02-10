package reachable

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"code.cfops.it/sys/tubular/internal"
	"code.cfops.it/sys/tubular/internal/log"
	"code.cfops.it/sys/tubular/internal/testutil"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/client_golang/prometheus"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"
)

func TestReachable(t *testing.T) {
	// For these tests use the current netns, the netns is created by
	// TestMain.
	netns, err := ns.GetNS("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}

	// Create the dispatcher
	dp := mustCreateDispatcher(t, netns)

	// Make some bindings
	bindings := internal.Bindings{
		mustNewBinding(t, "foo", internal.TCP, "::1/128", 8080),
		mustNewBinding(t, "foo", internal.TCP, "127.0.0.1", 0),
		mustNewBinding(t, "foo", internal.TCP, "127.0.0.1", 8080),
		mustNewBinding(t, "foo", internal.TCP, "127.0.0.1", 8081),
		mustNewBinding(t, "foo", internal.UDP, "127.0.0.1", 443),
	}

	// Add those bindings to the dispatcher
	for _, b := range bindings {
		mustAddBinding(t, dp, b)
	}
	dp.Close()

	logger := log.NewStdLogger(os.Stdout)

	// Initialise the prometheus registry and the reachability collector
	reg := prometheus.NewPedanticRegistry()
	c := NewReachable(logger, bindings)
	if err := reg.Register(c); err != nil {
		t.Fatal("Can't register:", err)
	}

	// Do one collection and ensure that we get unreachable
	want := map[string]float64{
		`bindings_unreachable_error{domain="ipv4", label="foo", protocol="tcp"}`: 0,
		`bindings_unreachable_error{domain="ipv6", label="foo", protocol="tcp"}`: 0,
		`bindings_unreachable{domain="ipv4", label="foo", protocol="tcp"}`:       3,
		`bindings_unreachable{domain="ipv6", label="foo", protocol="tcp"}`:       1,
	}
	if diff := cmp.Diff(want, testutil.FlattenMetrics(t, reg)); diff != "" {
		t.Errorf("Metrics don't match (-want +got):\n%s", diff)
	}

	// Create one listening socket and register it
	ln := testutil.Listen(t, netns, "tcp4", "").(*net.TCPListener)
	dp = mustOpenDispatcher(t, netns)
	mustRegisterSocket(t, dp, "foo", ln)
	dp.Close()

	// Do another collection to see how the reachability has changed
	want = map[string]float64{
		`bindings_unreachable_error{domain="ipv4", label="foo", protocol="tcp"}`: 0,
		`bindings_unreachable_error{domain="ipv6", label="foo", protocol="tcp"}`: 0,
		`bindings_unreachable{domain="ipv4", label="foo", protocol="tcp"}`:       0,
		`bindings_unreachable{domain="ipv6", label="foo", protocol="tcp"}`:       1,
	}

	if diff := cmp.Diff(want, testutil.FlattenMetrics(t, reg)); diff != "" {
		t.Errorf("Metrics don't match (-want +got):\n%s", diff)
	}

	// Create another listening socket and register it
	ln = testutil.Listen(t, netns, "tcp6", "").(*net.TCPListener)
	dp = mustOpenDispatcher(t, netns)
	mustRegisterSocket(t, dp, "foo", ln)
	dp.Close()

	// Do another collection to see how the reachability has changed
	want = map[string]float64{
		`bindings_unreachable_error{domain="ipv4", label="foo", protocol="tcp"}`: 0,
		`bindings_unreachable_error{domain="ipv6", label="foo", protocol="tcp"}`: 0,
		`bindings_unreachable{domain="ipv4", label="foo", protocol="tcp"}`:       0,
		`bindings_unreachable{domain="ipv6", label="foo", protocol="tcp"}`:       0,
	}

	if diff := cmp.Diff(want, testutil.FlattenMetrics(t, reg)); diff != "" {
		t.Errorf("Metrics don't match (-want +got):\n%s", diff)
	}
}

func TestLintReachable(t *testing.T) {
	netns := testutil.CurrentNetNS(t)
	dp := mustCreateDispatcher(t, netns)
	dp.Close()

	c := NewReachable(log.Discard, nil)

	lints, err := promtest.CollectAndLint(c)
	if err != nil {
		t.Fatal(err)
	}

	for _, lint := range lints {
		t.Errorf("%s: %s", lint.Metric, lint.Text)
	}
}

func TestMain(m *testing.M) {

	// We want to run these tests in a separate network namespace.
	// To do that reliably, we want to have the process and all its
	// threads to be executed in that namespace. So we execute ourselves
	// and set an environment variable so the nested execution knows not
	// to re-execute.
	_, set := os.LookupEnv("TEST_EXECUTED")
	if !set {
		var cmd = exec.Cmd{
			Path:   os.Args[0],
			Args:   os.Args,
			Env:    append(os.Environ(), "TEST_EXECUTED=true"),
			Stdin:  os.Stdin,
			Stdout: os.Stdout,
			Stderr: os.Stderr,
			SysProcAttr: &syscall.SysProcAttr{
				Cloneflags: syscall.CLONE_NEWNET,
			},
		}
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			os.Exit(1)
		}
	} else {
		if err := testutil.SetupLoopback(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			os.Exit(1)
		}
		os.Exit(m.Run())
	}
}

func mustNewBinding(tb testing.TB, label string, proto internal.Protocol, prefix string, port uint16) *internal.Binding {
	tb.Helper()

	bdg, err := internal.NewBinding(label, proto, prefix, port)
	if err != nil {
		tb.Fatal("Can't create binding:", err)
	}

	return bdg
}

func mustAddBinding(tb testing.TB, dp *internal.Dispatcher, bind *internal.Binding) {
	tb.Helper()

	if err := dp.AddBinding(bind); err != nil {
		tb.Fatal("Can't add binding:", err)
	}
}

func mustRegisterSocket(tb testing.TB, dp *internal.Dispatcher, label string, conn syscall.Conn) *internal.Destination {
	tb.Helper()

	dest, _, err := dp.RegisterSocket(label, conn)
	if err != nil {
		tb.Fatal("Register socket:", err)
	}

	return dest
}

func mustCreateDispatcher(tb testing.TB, netns ns.NetNS) *internal.Dispatcher {
	tb.Helper()

	var dp *internal.Dispatcher
	err := testutil.WithCapabilities(func() (err error) {
		dp, err = internal.CreateDispatcher(netns.Path(), "/sys/fs/bpf")
		return
	}, internal.CreateCapabilities...)
	if err != nil {
		tb.Fatal("Can't create dispatcher:", err)
	}

	tb.Cleanup(func() {
		os.RemoveAll(dp.Path)
		dp.Close()
	})
	return dp
}

func mustOpenDispatcher(tb testing.TB, netns ns.NetNS) *internal.Dispatcher {
	tb.Helper()

	dp, err := internal.OpenDispatcher(netns.Path(), "/sys/fs/bpf", false)
	if err != nil {
		tb.Fatal("Can't open dispatcher:", err)
	}

	return dp
}
