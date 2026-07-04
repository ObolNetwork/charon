// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package health

import (
	"strconv"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

func TestScrapeHighCardinality(t *testing.T) {
	registry := prometheus.NewRegistry()

	highVec := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_high_cardinality_metric", Help: "test"}, []string{"label"})
	lowVec := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_low_cardinality_metric", Help: "test"}, []string{"label"})
	registry.MustRegister(highVec, lowVec)

	for i := range seriesCardinalityThreshold + 1 {
		highVec.WithLabelValues(strconv.Itoa(i)).Set(1)
	}

	lowVec.WithLabelValues("0").Set(1)

	checker := NewChecker(Metadata{}, registry, 1)
	require.NoError(t, checker.scrape())

	require.InDelta(t, float64(seriesCardinalityThreshold+1),
		testutil.ToFloat64(highCardinalityGauge.WithLabelValues("test_high_cardinality_metric")), 0)
	require.InDelta(t, float64(0),
		testutil.ToFloat64(highCardinalityGauge.WithLabelValues("test_low_cardinality_metric")), 0)
}
