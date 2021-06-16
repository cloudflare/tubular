package reachable

import (
	"context"
	"errors"
	"math"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"code.cfops.it/sys/tubular/internal"
	"code.cfops.it/sys/tubular/internal/log"
	"github.com/prometheus/client_golang/prometheus"
	"inet.af/netaddr"
)

type key struct {
	label    string
	protocol internal.Protocol
	domain   internal.Domain
}

type Reachable struct {
	logger              log.Logger
	bindings            map[key]internal.Bindings
	bindingsUnreachable *prometheus.Desc
	errors              *prometheus.Desc
}

func NewReachable(logger log.Logger, bindings internal.Bindings) *Reachable {
	rand.Seed(time.Now().UnixNano())

	bindingsMap := makeBindingsMap(bindings)

	return &Reachable{
		logger,
		bindingsMap,
		prometheus.NewDesc(
			"bindings_unreachable",
			"The number of unreachable bindings.",
			[]string{"label", "protocol", "domain"},
			nil,
		),
		prometheus.NewDesc(
			"bindings_unreachable_error",
			"The number of errors occured when trying to check binding reachability.",
			[]string{"label", "protocol", "domain"},
			nil,
		),
	}
}

func (r *Reachable) Describe(ch chan<- *prometheus.Desc) {
	ch <- r.bindingsUnreachable
	ch <- r.errors
}

func (r *Reachable) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for labels, bindings := range r.bindings {
		if labels.protocol != internal.TCP {
			continue
		}

		commonLabels := []string{
			labels.label,
			labels.protocol.String(),
			labels.domain.String(),
		}

		var unreachableCount uint64 = 0
		var errorsCount uint64 = 0

		var wg sync.WaitGroup
		for _, binding := range bindings {
			wg.Add(1)
			go func(binding *internal.Binding) {
				defer wg.Done()
				ok, err := isBindingReachable(ctx, *binding)
				if err != nil {
					atomic.AddUint64(&errorsCount, 1)
					r.logger.Logf("the binding for label: %v, prefix: %v, protocol %v, port: %d was unreachable with error: %v", binding.Label, binding.Prefix, binding.Protocol, binding.Port, err)
					return
				}
				if !ok {
					atomic.AddUint64(&unreachableCount, 1)
					r.logger.Logf("the binding for label: %v, prefix: %v, protocol %v, port: %d was unreachable", binding.Label, binding.Prefix, binding.Protocol, binding.Port)
				}
			}(binding)
		}
		wg.Wait()

		ch <- prometheus.MustNewConstMetric(
			r.errors,
			prometheus.CounterValue,
			float64(errorsCount),
			commonLabels...,
		)

		ch <- prometheus.MustNewConstMetric(
			r.bindingsUnreachable,
			prometheus.GaugeValue,
			float64(unreachableCount),
			commonLabels...,
		)
	}
}

func makeBindingsMap(bindings internal.Bindings) map[key]internal.Bindings {
	bindingsMap := make(map[key]internal.Bindings)

	for _, binding := range bindings {
		domain := internal.AF_INET
		if binding.Prefix.IP().Unmap().Is6() {
			domain = internal.AF_INET6
		}
		mapKey := key{
			label:    binding.Label,
			protocol: binding.Protocol,
			domain:   domain,
		}

		bindingsMap[mapKey] = append(bindingsMap[mapKey], binding)
	}
	return bindingsMap
}

func isBindingReachable(ctx context.Context, b internal.Binding) (bool, error) {
	// We don't support checking non-TCP services yet
	if b.Protocol != internal.TCP {
		return false, errors.New("reachable check called for non-TCP binding")
	}

	laddr := netaddr.IPv4(127, 0, 0, 1)

	if b.Prefix.IP().Unmap().Is6() {
		laddr = netaddr.IPv6Raw([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	}

	// if port is 0, then randomise port
	port := b.Port
	if port == 0 {
		port = 1 + uint16(rand.Intn(int(math.MaxUint16-1)))
	}

	// TODO: Get random IP from prefix
	ipPort := netaddr.IPPortFrom(b.Prefix.IP(), port).TCPAddr().String()
	dialer := net.Dialer{
		Timeout: time.Second,
		// Dialing with a source port of 0 will allocate a random source
		// port.
		// Using a LocalAddr that is the loopback address will prevent
		// the connection from being routed away from the loopback
		// interface and onto the internet.
		LocalAddr: netaddr.IPPortFrom(laddr, 0).TCPAddr(),
	}

	conn, err := dialer.DialContext(ctx, "tcp", ipPort)
	// For unreachable bindings we expect ECONNREFUSED, so it's not
	// really an error.
	if errors.Is(err, syscall.ECONNREFUSED) {
		return false, nil
	} else if err != nil {
		return false, err
	}

	conn.Close()
	return true, nil
}
