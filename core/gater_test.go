// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

	// Allow slots 0-5.
	require.True(t, gater(core.Duty{Slot: 0})) // Current epoch
	require.True(t, gater(core.Duty{Slot: 1}))
	require.True(t, gater(core.Duty{Slot: 2})) // N+1 epoch
	require.True(t, gater(core.Duty{Slot: 3}))
	require.True(t, gater(core.Duty{Slot: 4})) // N+2 epoch
	require.True(t, gater(core.Duty{Slot: 5}))

	// Disallow slots 6 and after.
	require.False(t, gater(core.Duty{Slot: 6})) // N+3 epoch
	require.False(t, gater(core.Duty{Slot: 7}))
	require.False(t, gater(core.Duty{Slot: 1000}))
}
