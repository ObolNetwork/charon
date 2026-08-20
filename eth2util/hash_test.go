// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2util_test

import (
	"encoding/hex"
	"math"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/testutil"
)

func TestSlotHashRoot(t *testing.T) {
	tests := []struct {
		name string
		slot eth2p0.Slot
	}{
		{
			name: "zero",
			slot: 0,
		},
		{
			name: "one",
			slot: 1,
		},
		{
			name: "epoch_boundary",
			slot: 32000,
		},
		{
			name: "max_uint64",
			slot: math.MaxUint64,
		},
	}

	roots := make(map[string]string)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := eth2util.SlotHashRoot(tt.slot)
			require.NoError(t, err)

			roots[tt.name] = hex.EncodeToString(got[:])
		})
	}

	testutil.RequireGoldenJSON(t, roots)
}
