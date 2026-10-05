// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap_test

import (
	"encoding/hex"
	"math"
	"testing"
	"time"

	eth2spec "github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestFetchGenesisTime(t *testing.T) {
	eth2Cl, err := beaconmock.New(t.Context())
	require.NoError(t, err)

	genesisTime, err := eth2wrap.FetchGenesisTime(t.Context(), eth2Cl)
	require.NoError(t, err)

	// Matching beaconmock/static.json
	require.EqualValues(t, 1646092800, genesisTime.Unix())
}

func TestFetchSlotsConfig(t *testing.T) {
	eth2Cl, err := beaconmock.New(t.Context())
	require.NoError(t, err)

	slotDuration, slotsPerEpoch, err := eth2wrap.FetchSlotsConfig(t.Context(), eth2Cl)
	require.NoError(t, err)

	// Matching beaconmock/static.json
	require.Equal(t, 12*time.Second, slotDuration)
	require.EqualValues(t, 16, slotsPerEpoch)
}

func TestFetchSlotTimingConfig(t *testing.T) {
	eth2Cl, err := beaconmock.New(t.Context(),
		beaconmock.WithSpecOverride("ATTESTATION_DUE_BPS", "2000"),
		beaconmock.WithSpecOverride("ATTESTATION_DUE_BPS_GLOAS", "1500"),
	)
	require.NoError(t, err)

	timing, err := eth2wrap.FetchSlotTimingConfig(t.Context(), eth2Cl)
	require.NoError(t, err)

	require.Equal(t, eth2wrap.SlotTimingConfig{
		Attestation: eth2wrap.ForkBPS{PreGloas: 2000, Gloas: 1500},
		// Keys the beacon node doesn't publish default to the consensus spec values.
		Aggregate:          eth2wrap.ForkBPS{PreGloas: 6667, Gloas: 5000},
		SyncMessage:        eth2wrap.ForkBPS{PreGloas: 3333, Gloas: 2500},
		Contribution:       eth2wrap.ForkBPS{PreGloas: 6667, Gloas: 5000},
		Payload:            eth2wrap.ForkBPS{Gloas: 5000},
		PayloadAttestation: eth2wrap.ForkBPS{Gloas: 7500},
	}, timing)
}

func TestFetchForkConfig(t *testing.T) {
	eth2Cl, err := beaconmock.New(t.Context())
	require.NoError(t, err)

	forkConfig, err := eth2wrap.FetchForkConfig(t.Context(), eth2Cl)
	require.NoError(t, err)

	aVersion, err := hex.DecodeString("20000910")
	require.NoError(t, err)
	bVersion, err := hex.DecodeString("30000910")
	require.NoError(t, err)
	cVersion, err := hex.DecodeString("40000910")
	require.NoError(t, err)
	dVersion, err := hex.DecodeString("50000910")
	require.NoError(t, err)
	eVersion, err := hex.DecodeString("60000910")
	require.NoError(t, err)
	fVersion, err := hex.DecodeString("70000910")
	require.NoError(t, err)

	ffs := eth2wrap.ForkForkSchedule{
		eth2wrap.Altair:    eth2wrap.ForkSchedule{Epoch: 0, Version: [4]byte(aVersion)},
		eth2wrap.Bellatrix: eth2wrap.ForkSchedule{Epoch: 0, Version: [4]byte(bVersion)},
		eth2wrap.Capella:   eth2wrap.ForkSchedule{Epoch: 0, Version: [4]byte(cVersion)},
		eth2wrap.Deneb:     eth2wrap.ForkSchedule{Epoch: 0, Version: [4]byte(dVersion)},
		eth2wrap.Electra:   eth2wrap.ForkSchedule{Epoch: 2048, Version: [4]byte(eVersion)},
		eth2wrap.Fulu:      eth2wrap.ForkSchedule{Epoch: 18446744073709551615, Version: [4]byte(fVersion)},
		// Gloas spec keys are absent from beaconmock/static.json, so the optional fork resolves to unscheduled.
		eth2wrap.Gloas: eth2wrap.ForkSchedule{Epoch: math.MaxUint64},
	}

	// Matching beaconmock/static.json
	require.Equal(t, forkConfig, ffs)
}

func TestFetchForkConfigGloasScheduled(t *testing.T) {
	eth2Cl, err := beaconmock.New(
		t.Context(),
		beaconmock.WithSpecOverride("GLOAS_FORK_VERSION", "0x80000910"),
		beaconmock.WithSpecOverride("GLOAS_FORK_EPOCH", "4096"),
	)
	require.NoError(t, err)

	forkConfig, err := eth2wrap.FetchForkConfig(t.Context(), eth2Cl)
	require.NoError(t, err)

	gVersion, err := hex.DecodeString("80000910")
	require.NoError(t, err)

	require.Equal(t, eth2wrap.ForkSchedule{Epoch: 4096, Version: [4]byte(gVersion)}, forkConfig[eth2wrap.Gloas])
}

func TestForkForkScheduleActive(t *testing.T) {
	ffs := eth2wrap.ForkForkSchedule{
		eth2wrap.Electra: eth2wrap.ForkSchedule{Epoch: 2048},
		eth2wrap.Gloas:   eth2wrap.ForkSchedule{Epoch: math.MaxUint64},
	}

	require.True(t, ffs.Active(eth2wrap.Electra, 2048))
	require.True(t, ffs.Active(eth2wrap.Electra, 5000))
	require.False(t, ffs.Active(eth2wrap.Electra, 2047))

	// Unscheduled forks are never active, even at the far-future sentinel epoch.
	require.False(t, ffs.Active(eth2wrap.Gloas, 5000))
	require.False(t, ffs.Active(eth2wrap.Gloas, math.MaxUint64))

	// Forks absent from the schedule are never active.
	require.False(t, ffs.Active(eth2wrap.Fulu, 5000))
}

func TestForkForkScheduleDataVersion(t *testing.T) {
	const unscheduled = math.MaxUint64

	schedule := eth2wrap.ForkForkSchedule{
		eth2wrap.Altair:    {Epoch: 0},
		eth2wrap.Bellatrix: {Epoch: 0},
		eth2wrap.Capella:   {Epoch: 0},
		eth2wrap.Deneb:     {Epoch: 10},
		eth2wrap.Electra:   {Epoch: 20},
		eth2wrap.Fulu:      {Epoch: 30},
		eth2wrap.Gloas:     {Epoch: unscheduled},
	}

	tests := []struct {
		epoch eth2p0.Epoch
		want  eth2spec.DataVersion
	}{
		{epoch: 0, want: eth2spec.DataVersionCapella},
		{epoch: 9, want: eth2spec.DataVersionCapella},
		{epoch: 10, want: eth2spec.DataVersionDeneb},
		{epoch: 25, want: eth2spec.DataVersionElectra},
		{epoch: 30, want: eth2spec.DataVersionFulu},
		{epoch: 1000, want: eth2spec.DataVersionFulu}, // Gloas unscheduled.
	}

	for _, test := range tests {
		require.Equal(t, test.want, schedule.DataVersion(test.epoch), "epoch %d", test.epoch)
	}

	// Gloas scheduled.
	schedule[eth2wrap.Gloas] = eth2wrap.ForkSchedule{Epoch: 40}
	require.Equal(t, eth2spec.DataVersionFulu, schedule.DataVersion(39))
	require.Equal(t, eth2spec.DataVersionGloas, schedule.DataVersion(40))

	// No fork active resolves to phase0.
	require.Equal(t, eth2spec.DataVersionPhase0, eth2wrap.ForkForkSchedule{}.DataVersion(0))
}
