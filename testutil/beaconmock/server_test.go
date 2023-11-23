// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package beaconmock_test

import (
	"context"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestStatic(t *testing.T) {
	ctx := context.Background()

	eth2Cl, err := beaconmock.New()
	require.NoError(t, err)

	genesisResp, err := eth2Cl.Genesis(ctx, &eth2api.GenesisOpts{})
	require.NoError(t, err)
	require.Equal(t, "2022-03-01 00:00:00 +0000 UTC", genesisResp.Data.GenesisTime.UTC().String())

	configResp, err := eth2Cl.Spec(ctx, &eth2api.SpecOpts{})
	require.NoError(t, err)
	require.Equal(t, uint64(36660), configResp.Data["ALTAIR_FORK_EPOCH"])

	contractResp, err := eth2Cl.DepositContract(ctx, &eth2api.DepositContractOpts{})
	require.NoError(t, err)
	require.Equal(t, uint64(5), contractResp.Data.ChainID)

	spec, err := eth2Cl.Spec(ctx, &eth2api.SpecOpts{})
	require.NoError(t, err)
	slotsPerEpoch, ok := spec.Data["SLOTS_PER_EPOCH"].(uint64)
	require.True(t, ok)
	require.Equal(t, uint64(16), slotsPerEpoch)

	stateResp, err := eth2Cl.NodeSyncing(ctx, &eth2api.NodeSyncingOpts{})
	require.NoError(t, err)
	require.False(t, stateResp.Data.IsSyncing)

	versionResp, err := eth2Cl.NodeVersion(ctx, &eth2api.NodeVersionOpts{})
	require.NoError(t, err)
	require.Equal(t, "charon/static_beacon_mock", versionResp.Data)
}

func TestGenesisTimeOverride(t *testing.T) {
	ctx := context.Background()

	t0 := time.Now().Truncate(time.Second)
	eth2Cl, err := beaconmock.New(beaconmock.WithGenesisTime(t0))
	require.NoError(t, err)

	genesisResp, err := eth2Cl.Genesis(ctx, &eth2api.GenesisOpts{})
	require.NoError(t, err)
	require.Equal(t, t0, genesisResp.Data.GenesisTime)

	genesisTime, err := eth2Cl.GenesisTime(ctx)
	require.NoError(t, err)
	require.Equal(t, t0, genesisTime)
}

func TestSlotsPerEpochOverride(t *testing.T) {
	ctx := context.Background()

	expect := 5
	eth2Cl, err := beaconmock.New(beaconmock.WithSlotsPerEpoch(expect))
	require.NoError(t, err)

	spec, err := eth2Cl.Spec(ctx, &eth2api.SpecOpts{})
	require.NoError(t, err)
	actual, ok := spec.Data["SLOTS_PER_EPOCH"].(uint64)
	require.True(t, ok)

	require.EqualValues(t, expect, actual)

	specResp, err := eth2Cl.Spec(ctx, &eth2api.SpecOpts{})
	require.NoError(t, err)
	require.EqualValues(t, expect, specResp.Data["SLOTS_PER_EPOCH"])
}

func TestSlotsDurationOverride(t *testing.T) {
	ctx := context.Background()

	expect := time.Second
	eth2Cl, err := beaconmock.New(beaconmock.WithSlotDuration(expect))
	require.NoError(t, err)

	eth2Resp, err := eth2Cl.Spec(ctx, &eth2api.SpecOpts{})
	require.NoError(t, err)

	actual, ok := eth2Resp.Data["SECONDS_PER_SLOT"].(time.Duration)
	require.True(t, ok)
	require.NoError(t, err)
	require.EqualValues(t, expect, actual)

	specResp, err := eth2Cl.Spec(ctx, &eth2api.SpecOpts{})
	require.NoError(t, err)
	require.EqualValues(t, expect, specResp.Data["SECONDS_PER_SLOT"])
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

	fsResp, err := bmock.ForkSchedule(ctx, &eth2api.ForkScheduleOpts{})
	require.NoError(t, err)
	require.Len(t, fsResp.Data, 1)
	require.EqualValues(t, [4]byte{}, fsResp.Data[0].CurrentVersion)
	require.EqualValues(t, [4]byte{0x12, 0x34, 0x56, 0x78}, fsResp.Data[0].PreviousVersion)
}

func TestDefaultOverrides(t *testing.T) {
	ctx := context.Background()
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	resp, err := bmock.Spec(ctx, &eth2api.SpecOpts{})
	require.NoError(t, err)
	spec := resp.Data

	require.Equal(t, "charon-simnet", spec["CONFIG_NAME"])
	require.EqualValues(t, 16, spec["SLOTS_PER_EPOCH"])

	spec1, err := bmock.Spec(ctx, &eth2api.SpecOpts{})
	require.NoError(t, err)
	slotsPerEpoch, ok := spec1.Data["SLOTS_PER_EPOCH"].(uint64)
	require.True(t, ok)
	require.EqualValues(t, 16, slotsPerEpoch)

	genesis, err := bmock.GenesisTime(ctx)
	require.NoError(t, err)
	require.Equal(t, "2022-03-01 00:00:00 +0000 UTC", genesis.UTC().String())
}
