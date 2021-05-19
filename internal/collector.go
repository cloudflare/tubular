package internal

import (
	"fmt"

	"code.cfops.it/sys/tubular/internal/log"
	"github.com/prometheus/client_golang/prometheus"
)

// Collector exposes metrics from a Dispatcher in the Prometheus format.
type Collector struct {
	logger             log.Logger
	netnsPath          string
	bpffsPath          string
	collectionErrors   prometheus.Counter
	lookups            *prometheus.Desc
	misses             *prometheus.Desc
	errors             *prometheus.Desc
	bindings           *prometheus.Desc
	destinationSockets *prometheus.Desc
}

var _ prometheus.Collector = (*Collector)(nil)

func NewCollector(logger log.Logger, netnsPath, bpfFsPath string) *Collector {
	return &Collector{
		logger,
		netnsPath,
		bpfFsPath,
		prometheus.NewCounter(prometheus.CounterOpts{
			Name: "collection_errors_total",
			Help: "The number of times metrics collection encountered an error.",
		}),
		prometheus.NewDesc(
			"lookups_total",
			"Total number of times traffic matched a destination.",
			[]string{"label", "domain", "protocol"},
			nil,
		),
		prometheus.NewDesc(
			"misses_total",
			"Total number of failed lookups since no socket was registered.",
			[]string{"label", "domain", "protocol"},
			nil,
		),
		prometheus.NewDesc(
			"errors_total",
			"Total number of failed lookups due to an error.",
			[]string{"label", "domain", "protocol", "reason"},
			nil,
		),
		prometheus.NewDesc(
			"bindings",
			"The number of bindings for each label.",
			[]string{"label", "domain", "protocol"},
			nil,
		),
		prometheus.NewDesc(
			"destination_has_socket",
			"Whether or not a destination has a registered socket.",
			[]string{"label", "domain", "protocol"},
			nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	c.collectionErrors.Describe(ch)
	ch <- c.lookups
	ch <- c.misses
	ch <- c.errors
	ch <- c.bindings
	ch <- c.destinationSockets
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	// Collect last, so that errors during this collection are reflected.
	defer c.collectionErrors.Collect(ch)

	metrics, err := c.metrics()
	if err != nil {
		c.logger.Log("Failed to collect metrics:", err)
		c.collectionErrors.Inc()
		return
	}

	for dest, destMetrics := range metrics.Destinations {
		commonLabels := []string{
			dest.Label,
			dest.Domain.String(),
			dest.Protocol.String(),
		}

		ch <- prometheus.MustNewConstMetric(
			c.lookups,
			prometheus.CounterValue,
			float64(destMetrics.Lookups),
			commonLabels...,
		)

		ch <- prometheus.MustNewConstMetric(
			c.misses,
			prometheus.CounterValue,
			float64(destMetrics.Misses),
			commonLabels...,
		)

		ch <- prometheus.MustNewConstMetric(
			c.errors,
			prometheus.CounterValue,
			float64(destMetrics.ErrorBadSocket),
			append(commonLabels, "bad-socket")...,
		)
	}

	for binding, metric := range metrics.Bindings {
		commonLabels := []string{
			binding.Label,
			binding.Domain.String(),
			binding.Protocol.String(),
		}

		ch <- prometheus.MustNewConstMetric(
			c.bindings,
			prometheus.GaugeValue,
			float64(metric),
			commonLabels...,
		)
	}

	for dest, present := range metrics.Sockets {
		commonLabels := []string{
			dest.Label,
			dest.Domain.String(),
			dest.Protocol.String(),
		}

		ch <- prometheus.MustNewConstMetric(
			c.destinationSockets,
			prometheus.GaugeValue,
			float64(present),
			commonLabels...,
		)
	}
}

func (c *Collector) metrics() (*Metrics, error) {
	dp, err := OpenDispatcher(c.logger, c.netnsPath, c.bpffsPath, true)
	if err != nil {
		return nil, fmt.Errorf("open dispatcher: %s", err)
	}
	defer dp.Close()

	return dp.Metrics()
}
