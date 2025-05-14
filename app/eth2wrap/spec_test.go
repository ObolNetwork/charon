// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap_test

import (
	"testing"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestFetchNetworkSpec(t *testing.T) {
	eth2Cl, err := beaconmock.New()
	require.NoError(t, err)

	spec, err := eth2wrap.FetchNetworkSpec(t.Context(), eth2Cl)
	require.NoError(t, err)

	// Matching beaconmock/static.json
	require.Equal(t, time.Unix(1695902100, 0), spec.GenesisTime)
	require.Equal(t, 12*time.Second, spec.SlotDuration)
	require.EqualValues(t, 16, spec.SlotsPerEpoch)
}

func TestEpochSlot(t *testing.T) {
	eth2Cl, err := beaconmock.New()
	require.NoError(t, err)

	spec, err := eth2wrap.FetchNetworkSpec(t.Context(), eth2Cl)
	require.NoError(t, err)

	slot := spec.EpochSlot(123)

	require.Equal(t, eth2p0.Slot(123*16), slot)
}

func TestSlotEpoch(t *testing.T) {
	eth2Cl, err := beaconmock.New()
	require.NoError(t, err)

	spec, err := eth2wrap.FetchNetworkSpec(t.Context(), eth2Cl)
	require.NoError(t, err)

	epoch := spec.SlotEpoch(123*16 + 1)

	require.Equal(t, eth2p0.Epoch(123), epoch)
}
