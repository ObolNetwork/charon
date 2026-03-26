// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2util_test

import (
	"encoding/hex"
	"math"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util"
)

func TestSlotHashRoot(t *testing.T) {
	tests := []struct {
		name     string
		slot     eth2p0.Slot
		expected string
	}{
		{
			name:     "zero",
			slot:     0,
			expected: "0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name:     "one",
			slot:     1,
			expected: "0100000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name:     "epoch_boundary",
			slot:     32000,
			expected: "007d000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name:     "max_uint64",
			slot:     math.MaxUint64,
			expected: "ffffffffffffffff000000000000000000000000000000000000000000000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := eth2util.SlotHashRoot(tt.slot)
			require.NoError(t, err)
			require.Equal(t, tt.expected, hex.EncodeToString(got[:]))
		})
	}
}
