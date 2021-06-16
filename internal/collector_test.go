package internal

import (
	"net"
	"testing"

	"code.cfops.it/sys/tubular/internal/log"
	"code.cfops.it/sys/tubular/internal/testutil"

	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/client_golang/prometheus"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"
)

func TestCollector(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, nil, netns)

	mustAddBinding(t, dp, mustNewBinding(t, "foo", TCP, "::1/64", 8080))
	mustAddBinding(t, dp, mustNewBinding(t, "bar", UDP, "127.0.0.1", 443))
	dp.Close()

	c := NewCollector(log.Discard, netns.Path(), "/sys/fs/bpf")
	reg := prometheus.NewPedanticRegistry()

	if err := reg.Register(c); err != nil {
		t.Fatal("Can't register:", err)
	}

	metrics := testutil.FlattenMetrics(t, reg)
	if len(metrics) == 0 {
		t.Error("Expected metrics after bindings are added")
	}

	// Register an unconnected UDP socket and connect it afterwards to
	// trigger bad-socket.
	dp = mustOpenDispatcher(t, nil, netns)
	conn := testutil.Listen(t, netns, "udp4", "").(*net.UDPConn)
	mustRegisterSocket(t, dp, "bar", conn)
	testutil.ConnectSocket(t, conn)
	dp.Close()

	t.Run("misses", func(t *testing.T) {
		for i := float64(0); i < 2; i++ {
			testutil.CanDial(t, netns, "tcp6", "[::1]:8080")

			want := map[string]float64{
				"collection_errors_total": 0,
				`errors_total{domain="ipv4", label="bar", protocol="udp", reason="bad-socket"}`: 0,
				`errors_total{domain="ipv6", label="foo", protocol="tcp", reason="bad-socket"}`: 0,
				`lookups_total{domain="ipv4", label="bar", protocol="udp"}`:                     0,
				`lookups_total{domain="ipv6", label="foo", protocol="tcp"}`:                     i + 1,
				`misses_total{domain="ipv4", label="bar", protocol="udp"}`:                      0,
				`misses_total{domain="ipv6", label="foo", protocol="tcp"}`:                      i + 1,
				`bindings{domain="ipv4", label="bar", protocol="udp"}`:                          1,
				`bindings{domain="ipv6", label="foo", protocol="tcp"}`:                          1,
				`destination_has_socket{domain="ipv4", label="bar", protocol="udp"}`:            1,
				`destination_has_socket{domain="ipv6", label="foo", protocol="tcp"}`:            0,
			}

			if diff := cmp.Diff(want, testutil.FlattenMetrics(t, reg)); diff != "" {
				t.Errorf("Metrics don't match (-want +got):\n%s", diff)
			}
		}
	})

	t.Run("errors", func(t *testing.T) {
		for i := float64(0); i < 2; i++ {
			testutil.CanDial(t, netns, "udp4", "127.0.0.1:443")

			want := map[string]float64{
				"collection_errors_total": 0,
				`errors_total{domain="ipv4", label="bar", protocol="udp", reason="bad-socket"}`: i + 1,
				`errors_total{domain="ipv6", label="foo", protocol="tcp", reason="bad-socket"}`: 0,
				`lookups_total{domain="ipv4", label="bar", protocol="udp"}`:                     i + 1,
				`lookups_total{domain="ipv6", label="foo", protocol="tcp"}`:                     2,
				`misses_total{domain="ipv4", label="bar", protocol="udp"}`:                      0,
				`misses_total{domain="ipv6", label="foo", protocol="tcp"}`:                      2,
				`bindings{domain="ipv4", label="bar", protocol="udp"}`:                          1,
				`bindings{domain="ipv6", label="foo", protocol="tcp"}`:                          1,
				`destination_has_socket{domain="ipv4", label="bar", protocol="udp"}`:            1,
				`destination_has_socket{domain="ipv6", label="foo", protocol="tcp"}`:            0,
			}

			if diff := cmp.Diff(want, testutil.FlattenMetrics(t, reg)); diff != "" {
				t.Errorf("Metrics don't match (-want +got):\n%s", diff)
			}
		}
	})
}

func TestLintCollector(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, nil, netns)
	dp.Close()

	c := NewCollector(log.Discard, netns.Path(), "/sys/fs/bpf")

	lints, err := promtest.CollectAndLint(c)
	if err != nil {
		t.Fatal(err)
	}

	for _, lint := range lints {
		t.Errorf("%s: %s", lint.Metric, lint.Text)
	}
}
