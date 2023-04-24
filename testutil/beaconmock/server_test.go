// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package beaconmock_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestStatic(t *testing.T) {
	ctx := context.Background()

	eth2Cl, err := beaconmock.New()
	require.NoError(t, err)

	gen, err := eth2Cl.Genesis(ctx)
	require.NoError(t, err)
	require.Equal(t, "2022-03-01 00:00:00 +0000 UTC", gen.GenesisTime.UTC().String())

	config, err := eth2Cl.Spec(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(36660), config["ALTAIR_FORK_EPOCH"])

	contract, err := eth2Cl.DepositContract(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(5), contract.ChainID)

	slotsPerEpoch, err := eth2Cl.SlotsPerEpoch(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(16), slotsPerEpoch)

	state, err := eth2Cl.NodeSyncing(ctx)
	require.NoError(t, err)
	require.False(t, state.IsSyncing)

	version, err := eth2Cl.NodeVersion(ctx)
	require.NoError(t, err)
	require.Equal(t, "charon/static_beacon_mock", version)
}

func TestGenesisTimeOverride(t *testing.T) {
	ctx := context.Background()

	t0 := time.Now().Truncate(time.Second)
	eth2Cl, err := beaconmock.New(beaconmock.WithGenesisTime(t0))
	require.NoError(t, err)

	gen, err := eth2Cl.Genesis(ctx)
	require.NoError(t, err)
	require.Equal(t, t0, gen.GenesisTime)

	t1, err := eth2Cl.GenesisTime(ctx)
	require.NoError(t, err)
	require.Equal(t, t0, t1)
}

func TestSlotsPerEpochOverride(t *testing.T) {
	ctx := context.Background()

	expect := 5
	eth2Cl, err := beaconmock.New(beaconmock.WithSlotsPerEpoch(expect))
	require.NoError(t, err)

	actual, err := eth2Cl.SlotsPerEpoch(ctx)
	require.NoError(t, err)
	require.EqualValues(t, expect, actual)

	spec, err := eth2Cl.Spec(ctx)
	require.NoError(t, err)
	require.EqualValues(t, expect, spec["SLOTS_PER_EPOCH"])
}

func TestSlotsDurationOverride(t *testing.T) {
	ctx := context.Background()

	expect := time.Second
	eth2Cl, err := beaconmock.New(beaconmock.WithSlotDuration(expect))
	require.NoError(t, err)

	actual, err := eth2Cl.SlotDuration(ctx)
	require.NoError(t, err)
	require.EqualValues(t, expect, actual)

	spec, err := eth2Cl.Spec(ctx)
	require.NoError(t, err)
	require.EqualValues(t, expect, spec["SECONDS_PER_SLOT"])
}

func TestEndpointOverride(t *testing.T) {
	ctx := context.Background()

	// Setup beaconmock
	forkSchedule := `{"data": [{
        	"previous_version": "0x12345678",
			"current_version": "0x00000000",
        	"epoch": "0"
      	}]}`
	bmock, err := beaconmock.New(
		beaconmock.WithEndpoint("/eth/v1/config/fork_schedule", forkSchedule),
	)
	require.NoError(t, err)

	fs, err := bmock.ForkSchedule(ctx)
	require.NoError(t, err)
	require.Len(t, fs, 1)
	require.EqualValues(t, [4]byte{}, fs[0].CurrentVersion)
	require.EqualValues(t, [4]byte{0x12, 0x34, 0x56, 0x78}, fs[0].PreviousVersion)
}

func TestDefaultOverrides(t *testing.T) {
	ctx := context.Background()
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	spec, err := bmock.Spec(ctx)
	require.NoError(t, err)

	require.Equal(t, "charon-simnet", spec["CONFIG_NAME"])
	require.EqualValues(t, 16, spec["SLOTS_PER_EPOCH"])

	slotsPerEpoch, err := bmock.SlotsPerEpoch(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 16, slotsPerEpoch)

	genesis, err := bmock.GenesisTime(ctx)
	require.NoError(t, err)
	require.Equal(t, "2022-03-01 00:00:00 +0000 UTC", genesis.UTC().String())
}
