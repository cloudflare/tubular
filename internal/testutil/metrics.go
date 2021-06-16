package testutil

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
)

func FlattenMetrics(tb testing.TB, g prometheus.Gatherer) map[string]float64 {
	tb.Helper()

	fams, err := g.Gather()
	if err != nil {
		tb.Fatal(err)
	}

	samples, err := expfmt.ExtractSamples(&expfmt.DecodeOptions{}, fams...)
	if err != nil {
		tb.Fatal(err)
	}

	result := make(map[string]float64)
	for _, sample := range samples {
		result[sample.Metric.String()] = float64(sample.Value)
	}
	return result
}
