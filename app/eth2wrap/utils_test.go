// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestFetchGenesisTime(t *testing.T) {
	eth2Cl, err := beaconmock.New()
	require.NoError(t, err)

	genesisTime, err := eth2wrap.FetchGenesisTime(t.Context(), eth2Cl)
	require.NoError(t, err)

	// Matching beaconmock/static.json
	require.EqualValues(t, 1646092800, genesisTime.Unix())
}

func TestFetchSlotsConfig(t *testing.T) {
	eth2Cl, err := beaconmock.New()
	require.NoError(t, err)

	slotDuration, slotsPerEpoch, err := eth2wrap.FetchSlotsConfig(t.Context(), eth2Cl)
	require.NoError(t, err)

	// Matching beaconmock/static.json
	require.Equal(t, 12*time.Second, slotDuration)
	require.EqualValues(t, 16, slotsPerEpoch)
}
