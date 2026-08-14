// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestDutyGater(t *testing.T) {
	now := time.Now()
	allowedFutureEpochs := 2

	// Allow slots 0-3.
	slotDuration := time.Second
	bmock, err := beaconmock.New(
		t.Context(),
		beaconmock.WithGenesisTime(now),
		beaconmock.WithSlotDuration(slotDuration),
		beaconmock.WithSlotsPerEpoch(2),
	)
	require.NoError(t, err)

	gater, err := core.NewDutyGater(context.Background(), bmock, core.WithDutyGaterForT(t,
		func() time.Time { return now },
		allowedFutureEpochs,
	))
	require.NoError(t, err)

	typ := core.DutyAttester

	// Allow slots 0-5.
	require.True(t, gater(core.Duty{Slot: 0, Type: typ})) // Current epoch
	require.True(t, gater(core.Duty{Slot: 1, Type: typ}))
	require.True(t, gater(core.Duty{Slot: 2, Type: typ})) // N+1 epoch
	require.True(t, gater(core.Duty{Slot: 3, Type: typ}))
	require.True(t, gater(core.Duty{Slot: 4, Type: typ})) // N+2 epoch
	require.True(t, gater(core.Duty{Slot: 5, Type: typ}))

	// Disallow slots 6 and after.
	require.False(t, gater(core.Duty{Slot: 6, Type: typ})) // N+3 epoch
	require.False(t, gater(core.Duty{Slot: 7, Type: typ}))
	require.False(t, gater(core.Duty{Slot: 1000, Type: typ}))

	// Disallow invalid type
	require.False(t, gater(core.Duty{Slot: 0, Type: -1}))
	require.False(t, gater(core.Duty{Slot: 1, Type: 0}))
	require.False(t, gater(core.Duty{Slot: 2, Type: 100}))
	require.False(t, gater(core.Duty{Slot: 3, Type: 1000}))
}

// TestDutyGaterInfoSync asserts the gater allows the info sync duties that infosync
// triggers in the last slot of each epoch. The priority protocol gates these duties on
// receipt, so rejecting them here would stall cluster wide priority resolution.
func TestDutyGaterInfoSync(t *testing.T) {
	const (
		slotDuration  = 12 * time.Second
		slotsPerEpoch = 32
		epoch         = 100
	)

	genesis := time.Now()

	bmock, err := beaconmock.New(
		t.Context(),
		beaconmock.WithGenesisTime(genesis),
		beaconmock.WithSlotDuration(slotDuration),
		beaconmock.WithSlotsPerEpoch(slotsPerEpoch),
	)
	require.NoError(t, err)

	// The slot infosync triggers on, being the last of its epoch.
	triggerSlot := uint64(epoch*slotsPerEpoch + slotsPerEpoch - 1)

	tests := []struct {
		name     string
		recvSlot uint64
	}{
		{name: "received in trigger slot", recvSlot: triggerSlot},
		// A peer lagging into the next epoch must still accept it, otherwise clock
		// skew across the cluster would drop legitimate exchanges.
		{name: "received in next epoch", recvSlot: triggerSlot + 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := genesis.Add(slotDuration * time.Duration(test.recvSlot))

			gater, err := core.NewDutyGater(t.Context(), bmock,
				core.WithDutyGaterForT(t, func() time.Time { return now }, 2))
			require.NoError(t, err)

			require.True(t, gater(core.NewInfoSyncDuty(triggerSlot)))
		})
	}
}
