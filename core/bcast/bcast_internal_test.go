// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package bcast

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestDelayFuncSpecOffsets(t *testing.T) {
	// The expected submission time of a duty is its spec-defined offset into the slot, so the
	// gloas deadlines report a larger delay than the pre-gloas deadlines for the same broadcast.
	preGloas, err := beaconmock.New(t.Context())
	require.NoError(t, err)

	gloas, err := beaconmock.New(t.Context(), beaconmock.WithSpecOverride("GLOAS_FORK_EPOCH", "0"))
	require.NoError(t, err)

	preGloasFunc, err := newDelayFunc(t.Context(), preGloas)
	require.NoError(t, err)

	gloasFunc, err := newDelayFunc(t.Context(), gloas)
	require.NoError(t, err)

	tests := []struct {
		dutyType core.DutyType
		expect   time.Duration // How much earlier the gloas deadline is, for a 12s slot duration.
	}{
		{dutyType: core.DutyAttester, expect: time.Second},       // 4s to 3s
		{dutyType: core.DutyAggregator, expect: 2 * time.Second}, // 8s to 6s
		{dutyType: core.DutySyncContribution, expect: 2 * time.Second},
		{dutyType: core.DutyProposer, expect: 0},    // Proposals are due at the start of the slot.
		{dutyType: core.DutySyncMessage, expect: 0}, // Charon reports sync messages from the start of the slot.
	}

	for _, test := range tests {
		t.Run(test.dutyType.String(), func(t *testing.T) {
			const slot = 100

			gloasDelay := gloasFunc(slot, test.dutyType)
			preGloasDelay := preGloasFunc(slot, test.dutyType)

			require.InDelta(t, test.expect, gloasDelay-preGloasDelay, float64(50*time.Millisecond))
		})
	}
}
