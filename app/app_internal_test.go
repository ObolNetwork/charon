// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestSlotFromTimestamp(t *testing.T) {
	tests := []struct {
		name      string
		slot      uint64
		network   string
		timestamp time.Time
	}{
		{
			name:      "goerli_slot0",
			slot:      0,
			network:   "goerli",
			timestamp: time.Unix(1616508000, 0).UTC(),
		},
		{
			name:      "goerli_slot1",
			slot:      1,
			network:   "goerli",
			timestamp: time.Unix(1616508000, 0).UTC().Add(time.Second * 12),
		},
		{
			name:      "sepolia_slot0",
			slot:      0,
			network:   "sepolia",
			timestamp: time.Unix(1655733600, 0).UTC(),
		},
		{
			name:      "sepolia_slot1",
			slot:      1,
			network:   "sepolia",
			timestamp: time.Unix(1655733600, 0).UTC().Add(time.Second * 12),
		},
		{
			name:      "gnosis_slot0",
			slot:      0,
			network:   "gnosis",
			timestamp: time.Unix(1638993340, 0).UTC(),
		},
		{
			name:      "gnosis_slot1",
			slot:      1,
			network:   "gnosis",
			timestamp: time.Unix(1638993340, 0).UTC().Add(time.Second * 12),
		},
		{
			name:      "mainnet_slot0",
			slot:      0,
			network:   "mainnet",
			timestamp: time.Unix(1606824023, 0).UTC(),
		},
		{
			name:      "mainnet_slot1",
			slot:      1,
			network:   "mainnet",
			timestamp: time.Unix(1606824023, 0).UTC().Add(time.Second * 12),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			genesis, err := eth2util.NetworkToGenesisTime(test.network)
			require.NoError(t, err)

			bmock, err := beaconmock.New(beaconmock.WithGenesisTime(genesis))
			require.NoError(t, err)

			slot, err := slotFromTimestamp(context.Background(), bmock, test.timestamp)
			require.NoError(t, err)
			require.Equal(t, test.slot, slot)
		})
	}
}
