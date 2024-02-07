// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package bcast

import (
	"bytes"
	"testing"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
)

func TestErrorsRate_IncrementTotal(t *testing.T) {
	var tracker errorsRate

	tracker.incrementTotal(core.Duty{
		Slot: 0, // Pregen
		Type: core.DutyBuilderRegistration,
	})
	tracker.incrementTotal(core.Duty{
		Slot: 1, // Downstream
		Type: core.DutyBuilderRegistration,
	})
	tracker.incrementTotal(core.Duty{
		Slot: 1,
		Type: core.DutyAggregator, // Shall be ignored
	})

	require.Equal(t, 1, tracker.pregenState.total)
	require.Equal(t, 1, tracker.downstreamState.total)
}

func TestErrorsRate_IncrementErrors(t *testing.T) {
	var tracker errorsRate

	tracker.incrementErrors(core.Duty{
		Slot: 0, // Pregen
		Type: core.DutyBuilderRegistration,
	})
	tracker.incrementErrors(core.Duty{
		Slot: 1, // Downstream
		Type: core.DutyBuilderRegistration,
	})
	tracker.incrementErrors(core.Duty{
		Slot: 1,
		Type: core.DutyAggregator, // Shall be ignored
	})

	require.Equal(t, 1, tracker.pregenState.errors)
	require.Equal(t, 1, tracker.downstreamState.errors)
}

func TestErrorsRate_UpdateMetrics(t *testing.T) {
	t.Run("low previous rate", func(t *testing.T) {
		tracker := errorsRate{
			pregenState: rateState{
				total:    1000,
				errors:   800,
				prevRate: 10,
			},
			downstreamState: rateState{
				total:    1000,
				errors:   800,
				prevRate: 10,
			},
		}

		tracker.updateMetrics() // Metric must not be populated

		err := promtest.CollectAndCompare(recastErrors, bytes.NewReader([]byte{}), "core_bcast_recast_errors")
		require.NoError(t, err)
	})

	t.Run("high previous rate", func(t *testing.T) {
		tracker := errorsRate{
			pregenState: rateState{
				total:    1000,
				errors:   800,
				prevRate: 71,
			},
			downstreamState: rateState{
				total:    1000,
				errors:   800,
				prevRate: 90,
			},
		}

		tracker.updateMetrics()

		expectedMetric := `
		# HELP core_bcast_recast_errors_rate The rate (percent) of failed recasted registrations by source; 'pregen' vs 'downstream'
		# TYPE core_bcast_recast_errors_rate gauge
		core_bcast_recast_errors_rate{source="downstream"} 80
		core_bcast_recast_errors_rate{source="pregen"} 80
		`

		err := promtest.CollectAndCompare(recastErrorsRate, bytes.NewReader([]byte(expectedMetric)), "core_bcast_recast_errors_rate")
		require.NoError(t, err)

		expectedMetric = `
		# HELP core_bcast_recast_total The total count of recasted registrations by source; 'pregen' vs 'downstream'
		# TYPE core_bcast_recast_total counter
		core_bcast_recast_total{source="downstream"} 2000
		core_bcast_recast_total{source="pregen"} 2000
				`

		err = promtest.CollectAndCompare(recastTotal, bytes.NewReader([]byte(expectedMetric)), "core_bcast_recast_total")
		require.NoError(t, err)

		expectedMetric = `
		# HELP core_bcast_recast_errors_total The total count of failed recasted registrations by source; 'pregen' vs 'downstream'
		# TYPE core_bcast_recast_errors_total counter
		core_bcast_recast_errors_total{source="downstream"} 1600
		core_bcast_recast_errors_total{source="pregen"} 1600
				`

		err = promtest.CollectAndCompare(recastErrors, bytes.NewReader([]byte(expectedMetric)), "core_bcast_recast_errors_total")
		require.NoError(t, err)
	})
}
