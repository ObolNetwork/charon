// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package promauto_test

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/promauto"
)

var testGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "test",
	Help: "",
}, []string{"label"})

func TestWrapRegisterer(t *testing.T) {
	testGauge.WithLabelValues("0").Set(1)

	labels := prometheus.Labels{
		"wrap_1": "1",
		"wrap_2": "2",
	}

	registry, err := promauto.NewRegistry(labels)
	require.NoError(t, err)
	metrics, err := registry.Gather()
	require.NoError(t, err)
	require.True(t, len(metrics) > 1)

	var foundTest bool
	for _, metricFam := range metrics {
		// All metrics contain own and registered labels.
		for _, metric := range metricFam.Metric {
			notFound := make(prometheus.Labels)
			for k, v := range labels {
				notFound[k] = v
			}
			for _, label := range metric.Label {
				v, ok := notFound[*label.Name]
				if !ok {
					continue
				}
				require.Equal(t, v, *label.Value)
				delete(notFound, *label.Name)
			}

			require.Empty(t, notFound)
		}
		if *metricFam.Name == "test" {
			foundTest = true
		}
	}

	require.True(t, foundTest)
}
