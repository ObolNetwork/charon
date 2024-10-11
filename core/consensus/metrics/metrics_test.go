// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package metrics_test

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	pb "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/promauto"
	"github.com/obolnetwork/charon/core/consensus/metrics"
)

func TestConsensusMetrics_SetDecidedRounds(t *testing.T) {
	cm := metrics.NewConsensusMetrics("test")

	cm.SetDecidedRounds("duty", "timer", 1)

	m := gatherMetric(t, "core_consensus_decided_rounds")
	require.InEpsilon(t, 1, m.GetMetric()[0].GetGauge().GetValue(), 0.0001)
}

func TestConsensusMetrics_ObserveConsensusDuration(t *testing.T) {
	cm := metrics.NewConsensusMetrics("test")

	cm.ObserveConsensusDuration("duty", "timer", 1)

	m := gatherMetric(t, "core_consensus_duration_seconds")
	require.EqualValues(t, 1, m.GetMetric()[0].GetHistogram().GetSampleCount())
}

func TestConsensusMetrics_IncConsensusTimeout(t *testing.T) {
	cm := metrics.NewConsensusMetrics("test")

	cm.IncConsensusTimeout("duty", "timer")

	m := gatherMetric(t, "core_consensus_timeout_total")
	require.InEpsilon(t, 1, m.GetMetric()[0].GetCounter().GetValue(), 0.0001)
}

func TestConsensusMetrics_IncConsensusError(t *testing.T) {
	cm := metrics.NewConsensusMetrics("test")

	cm.IncConsensusError()

	m := gatherMetric(t, "core_consensus_error_total")
	require.InEpsilon(t, 1, m.GetMetric()[0].GetCounter().GetValue(), 0.0001)
}

func gatherMetric(t *testing.T, name string) *pb.MetricFamily {
	t.Helper()

	labels := prometheus.Labels{}

	registry, err := promauto.NewRegistry(labels)
	require.NoError(t, err)

	mfa, err := registry.Gather()
	require.NoError(t, err)

	for _, mf := range mfa {
		if mf.GetName() == name {
			return mf
		}
	}

	require.Fail(t, "metric not found")

	return nil
}
