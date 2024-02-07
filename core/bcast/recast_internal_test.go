// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package bcast

import (
	"bytes"
	"testing"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
)

func TestUpdateRecastTotal(t *testing.T) {
	var pregenRate, downstreamRate rate

	t.Run("ignores other duties", func(t *testing.T) {
		d := core.Duty{
			Slot: 0,
			Type: core.DutyAggregator,
		}

		updateRecastTotal(d, &pregenRate, &downstreamRate)

		require.Equal(t, 0, pregenRate.total)
		require.Equal(t, 0, downstreamRate.total)
	})

	d := core.Duty{
		Slot: 0,
		Type: core.DutyBuilderRegistration,
	}

	t.Run("pregen source", func(t *testing.T) {
		updateRecastTotal(d, &pregenRate, &downstreamRate)

		require.Equal(t, 1, pregenRate.total)
		require.Equal(t, 0, downstreamRate.total)
	})

	t.Run("downstream source", func(t *testing.T) {
		d.Slot = 1
		updateRecastTotal(d, &pregenRate, &downstreamRate)

		require.Equal(t, 1, pregenRate.total)
		require.Equal(t, 1, downstreamRate.total)
	})

	metric := `
# HELP core_bcast_recast_total The total count of recasted registrations by source; 'pregen' vs 'downstream'
# TYPE core_bcast_recast_total counter
core_bcast_recast_total{source="downstream"} 1
core_bcast_recast_total{source="pregen"} 1
`

	err := promtest.CollectAndCompare(recastTotal, bytes.NewReader([]byte(metric)), "core_bcast_recast_total")
	require.NoError(t, err)
}

func TestUpdateRecastErrors(t *testing.T) {
	var pregenRate, downstreamRate rate

	t.Run("ignores other duties", func(t *testing.T) {
		d := core.Duty{
			Slot: 0,
			Type: core.DutyAggregator,
		}

		updateRecastErrors(d, &pregenRate, &downstreamRate)

		require.Equal(t, 0, pregenRate.count)
		require.Equal(t, 0, downstreamRate.count)
	})

	d := core.Duty{
		Slot: 0,
		Type: core.DutyBuilderRegistration,
	}

	t.Run("pregen source", func(t *testing.T) {
		updateRecastErrors(d, &pregenRate, &downstreamRate)

		require.Equal(t, 1, pregenRate.count)
		require.Equal(t, 0, downstreamRate.count)
	})

	t.Run("downstream source", func(t *testing.T) {
		d.Slot = 1
		updateRecastErrors(d, &pregenRate, &downstreamRate)

		require.Equal(t, 1, pregenRate.count)
		require.Equal(t, 1, downstreamRate.count)
	})

	metric := `
# HELP core_bcast_recast_errors_total The total count of failed recasted registrations by source; 'pregen' vs 'downstream'
# TYPE core_bcast_recast_errors_total counter
core_bcast_recast_errors_total{source="downstream"} 1
core_bcast_recast_errors_total{source="pregen"} 1
`

	err := promtest.CollectAndCompare(recastErrors, bytes.NewReader([]byte(metric)), "core_bcast_recast_errors")
	require.NoError(t, err)
}
