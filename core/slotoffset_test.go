// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestNewSlotOffsetFunc(t *testing.T) {
	bmock, err := beaconmock.New(t.Context())
	require.NoError(t, err)

	offsetFunc, err := core.NewSlotOffsetFunc(t.Context(), bmock)
	require.NoError(t, err)

	// Matching beaconmock's 12s slot duration, without the gloas fork scheduled.
	require.Equal(t, 4*time.Second, offsetFunc(core.Duty{Slot: 99, Type: core.DutyAttester}))
	require.Equal(t, 8*time.Second, offsetFunc(core.Duty{Slot: 99, Type: core.DutyAggregator}))
	require.Zero(t, offsetFunc(core.Duty{Slot: 99, Type: core.DutyProposer}))
}

func TestNewSlotOffsetFuncGloasScheduled(t *testing.T) {
	bmock, err := beaconmock.New(t.Context(), beaconmock.WithSpecOverride("GLOAS_FORK_EPOCH", "10"))
	require.NoError(t, err)

	offsetFunc, err := core.NewSlotOffsetFunc(t.Context(), bmock)
	require.NoError(t, err)

	// Matching beaconmock's 16 slots per epoch, so the fork starts at slot 160.
	require.Equal(t, 4*time.Second, offsetFunc(core.Duty{Slot: 159, Type: core.DutyAttester}))
	require.Equal(t, 3*time.Second, offsetFunc(core.Duty{Slot: 160, Type: core.DutyAttester}))
	require.Equal(t, 6*time.Second, offsetFunc(core.Duty{Slot: 160, Type: core.DutySyncContribution}))
}
