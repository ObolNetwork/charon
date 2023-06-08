// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package promauto_test

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/promauto"
)

const resetTest = "reset_test"

var testResetGauge = promauto.NewResetGaugeVec(prometheus.GaugeOpts{
	Name: resetTest,
	Help: "",
}, []string{"label"})

func TestResetGaugeVec(t *testing.T) {
	registry, err := promauto.NewRegistry(nil)
	require.NoError(t, err)

	testResetGauge.WithLabelValues("1").Set(1)
	assertVecLen(t, registry, resetTest, 1)

	testResetGauge.WithLabelValues("2").Set(2)
	assertVecLen(t, registry, resetTest, 2)

	testResetGauge.Reset()
	assertVecLen(t, registry, resetTest, 0)

	testResetGauge.WithLabelValues("3").Set(3)
	assertVecLen(t, registry, resetTest, 1)
}

func assertVecLen(t *testing.T, registry *prometheus.Registry, name string, l int) { //nolint:unparam // abstracting name is fine even though it is always currently constant
	t.Helper()

	metrics, err := registry.Gather()
	require.NoError(t, err)

	for _, metricFam := range metrics {
		if *metricFam.Name != name {
			continue
		}

		require.Len(t, metricFam.Metric, l)

		return
	}

	if l == 0 {
		return
	}

	require.Fail(t, "metric not found")
}
