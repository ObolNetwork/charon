// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package promauto_test

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/promauto"
)

const (
	resetTest      = "reset_test"
	resetTestExact = "reset_test_exact"
)

var (
	testResetGauge = promauto.NewResetGaugeVec(prometheus.GaugeOpts{
		Name: resetTest,
		Help: "",
	}, []string{"label0", "label1"})

	testResetGaugeExact = promauto.NewResetGaugeVec(prometheus.GaugeOpts{
		Name: resetTestExact,
		Help: "",
	}, []string{"label0", "label1"})
)

func TestResetGaugeVec(t *testing.T) {
	registry, err := promauto.NewRegistry(nil)
	require.NoError(t, err)

	testResetGauge.WithLabelValues("1", "a").Set(0)
	assertVecLen(t, registry, resetTest, 1)

	// Same labels, should not increase length
	testResetGauge.WithLabelValues("1", "a").Set(1)
	assertVecLen(t, registry, resetTest, 1)

	testResetGauge.WithLabelValues("2", "b").Set(2)
	assertVecLen(t, registry, resetTest, 2)

	testResetGauge.Reset()
	assertVecLen(t, registry, resetTest, 0)

	testResetGauge.WithLabelValues("3", "c").Set(3)
	assertVecLen(t, registry, resetTest, 1)

	testResetGauge.WithLabelValues("3", "d").Set(3)
	assertVecLen(t, registry, resetTest, 2)

	testResetGauge.WithLabelValues("3", "e").Set(3)
	assertVecLen(t, registry, resetTest, 3)

	testResetGauge.WithLabelValues("4", "z").Set(4)
	assertVecLen(t, registry, resetTest, 4)

	testResetGauge.Reset("3", "c")
	assertVecLen(t, registry, resetTest, 3)

	testResetGauge.Reset("3")
	assertVecLen(t, registry, resetTest, 1)
}

func TestResetGaugeVecExactPrefix(t *testing.T) {
	registry, err := promauto.NewRegistry(nil)
	require.NoError(t, err)

	// Label values may contain any characters, including "|".
	testResetGaugeExact.WithLabelValues("with|pipe", "a").Set(1)
	assertVecLen(t, registry, resetTestExact, 1)

	testResetGaugeExact.WithLabelValues("foobar", "b").Set(1)
	assertVecLen(t, registry, resetTestExact, 2)

	// Substring of a label value must not match.
	testResetGaugeExact.Reset("foo")
	assertVecLen(t, registry, resetTestExact, 2)

	// Non-leading label values must not match.
	testResetGaugeExact.Reset("a")
	assertVecLen(t, registry, resetTestExact, 2)

	testResetGaugeExact.Reset("foobar")
	assertVecLen(t, registry, resetTestExact, 1)

	testResetGaugeExact.Reset("with|pipe", "a")
	assertVecLen(t, registry, resetTestExact, 0)
}

func assertVecLen(t *testing.T, registry *prometheus.Registry, name string, l int) {
	t.Helper()

	metrics, err := registry.Gather()
	require.NoError(t, err)

	for _, metricFam := range metrics {
		if metricFam.GetName() != name {
			continue
		}

		require.Len(t, metricFam.GetMetric(), l)

		return
	}

	if l == 0 {
		return
	}

	require.Fail(t, "metric not found")
}
