// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap_test

import (
	"encoding/hex"
	"testing"
	"time"

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
	// fVersion, err := hex.DecodeString("70000910")
	// require.NoError(t, err)
	ffs := eth2wrap.ForkForkSchedule{
		eth2wrap.Altair:    eth2wrap.ForkSchedule{Epoch: 0, Version: [4]byte(aVersion)},
		eth2wrap.Bellatrix: eth2wrap.ForkSchedule{Epoch: 0, Version: [4]byte(bVersion)},
		eth2wrap.Capella:   eth2wrap.ForkSchedule{Epoch: 0, Version: [4]byte(cVersion)},
		eth2wrap.Deneb:     eth2wrap.ForkSchedule{Epoch: 0, Version: [4]byte(dVersion)},
		eth2wrap.Electra:   eth2wrap.ForkSchedule{Epoch: 2048, Version: [4]byte(eVersion)},
		// eth2wrap.Fulu:      eth2wrap.ForkSchedule{Epoch: 18446744073709551615, Version: [4]byte(fVersion)},
	}

	// Matching beaconmock/static.json
	require.Equal(t, forkConfig, ffs)
}
