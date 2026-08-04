// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseSlotTimingConfig(t *testing.T) {
	// specDefaults is the config returned when the beacon node publishes none of the keys.
	specDefaults := SlotTimingConfig{
		Attestation:  ForkBPS{PreGloas: 3333, Gloas: 2500},
		Aggregate:    ForkBPS{PreGloas: 6667, Gloas: 5000},
		SyncMessage:  ForkBPS{PreGloas: 3333, Gloas: 2500},
		Contribution: ForkBPS{PreGloas: 6667, Gloas: 5000},
		GloasEpoch:   math.MaxUint64,
	}

	tests := []struct {
		name    string
		data    map[string]any
		expect  SlotTimingConfig
		errorIs string
	}{
		{
			name:   "no keys published",
			data:   map[string]any{},
			expect: specDefaults,
		},
		{
			name: "all keys published",
			data: map[string]any{
				"ATTESTATION_DUE_BPS":         uint64(3333),
				"ATTESTATION_DUE_BPS_GLOAS":   uint64(2500),
				"AGGREGATE_DUE_BPS":           uint64(6667),
				"AGGREGATE_DUE_BPS_GLOAS":     uint64(5000),
				"SYNC_MESSAGE_DUE_BPS":        uint64(3333),
				"SYNC_MESSAGE_DUE_BPS_GLOAS":  uint64(2500),
				"CONTRIBUTION_DUE_BPS":        uint64(6667),
				"CONTRIBUTION_DUE_BPS_GLOAS":  uint64(5000),
				"GLOAS_FORK_EPOCH":            uint64(1024),
				"PAYLOAD_ATTESTATION_DUE_BPS": uint64(7500), // Unused, must be ignored.
			},
			expect: SlotTimingConfig{
				Attestation:  ForkBPS{PreGloas: 3333, Gloas: 2500},
				Aggregate:    ForkBPS{PreGloas: 6667, Gloas: 5000},
				SyncMessage:  ForkBPS{PreGloas: 3333, Gloas: 2500},
				Contribution: ForkBPS{PreGloas: 6667, Gloas: 5000},
				GloasEpoch:   1024,
			},
		},
		{
			name: "custom values override defaults",
			data: map[string]any{
				"ATTESTATION_DUE_BPS":       uint64(2000),
				"ATTESTATION_DUE_BPS_GLOAS": uint64(1500),
				"GLOAS_FORK_EPOCH":          uint64(0),
			},
			expect: SlotTimingConfig{
				Attestation:  ForkBPS{PreGloas: 2000, Gloas: 1500},
				Aggregate:    ForkBPS{PreGloas: 6667, Gloas: 5000},
				SyncMessage:  ForkBPS{PreGloas: 3333, Gloas: 2500},
				Contribution: ForkBPS{PreGloas: 6667, Gloas: 5000},
				GloasEpoch:   0,
			},
		},
		{
			name:    "basis points above slot duration",
			data:    map[string]any{"AGGREGATE_DUE_BPS": uint64(10001)},
			errorIs: "invalid basis points in network spec",
		},
		{
			name:    "zero basis points",
			data:    map[string]any{"SYNC_MESSAGE_DUE_BPS_GLOAS": uint64(0)},
			errorIs: "invalid basis points in network spec",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			timing, err := parseSlotTimingConfig(test.data)
			if test.errorIs != "" {
				require.ErrorContains(t, err, test.errorIs)

				return
			}

			require.NoError(t, err)
			require.Equal(t, test.expect, timing)
		})
	}
}
