// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"
)

// TestMarshal tests the marshal() internal function.
// marshal() uses SSZ when the type implements ssz.Marshaler and SSZ is enabled,
// otherwise falls back to JSON.
func TestMarshal(t *testing.T) {
	// adZeros is a zero-valued AttestationData with non-nil Source/Target (required for valid SSZ).
	adZeros := AttestationData{
		Data: eth2p0.AttestationData{
			Source: new(eth2p0.Checkpoint),
			Target: new(eth2p0.Checkpoint),
		},
	}

	// adValid is an AttestationData with non-zero fields, including CommitteeLength > 0
	// so that JSON roundtrip validation succeeds.
	adValid := AttestationData{
		Data: eth2p0.AttestationData{
			Slot:   10,
			Index:  2,
			Source: new(eth2p0.Checkpoint),
			Target: new(eth2p0.Checkpoint),
		},
		Duty: eth2v1.AttesterDuty{
			Slot:                    10,
			CommitteeIndex:          2,
			CommitteeLength:         128,
			CommitteesAtSlot:        1,
			ValidatorCommitteeIndex: 5,
		},
	}

	tests := []struct {
		name       string
		value      any
		expected   string
		disableSSZ bool
		hexCompare bool // true → compare hex(result); false → compare string(result)
	}{
		{
			name:       "attestation_data_zeros/ssz",
			value:      adZeros,
			hexCompare: true,
			expected:   "08000000880000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name:       "attestation_data_nozero/ssz",
			value:      adValid,
			hexCompare: true,
			expected:   "08000000880000000a000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000200000000000000800000000000000001000000000000000500000000000000",
		},
		{
			name:       "signature/json",
			value:      Signature{0xde, 0xad, 0xbe, 0xef},
			hexCompare: false,
			expected:   `"3q2+7w=="`,
		},
		{
			name:       "attestation_data_zeros/json_ssz_disabled",
			value:      adZeros,
			disableSSZ: true,
			hexCompare: false,
			expected:   `{"attestation_data":{"slot":"0","index":"0","beacon_block_root":"0x0000000000000000000000000000000000000000000000000000000000000000","source":{"epoch":"0","root":"0x0000000000000000000000000000000000000000000000000000000000000000"},"target":{"epoch":"0","root":"0x0000000000000000000000000000000000000000000000000000000000000000"}},"attestation_duty":{"pubkey":"0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","slot":"0","validator_index":"0","committee_index":"0","committee_length":"0","committees_at_slot":"0","validator_committee_index":"0"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.disableSSZ {
				DisableSSZMarshallingForT(t)
			}

			b, err := marshal(tt.value)
			require.NoError(t, err)

			if tt.hexCompare {
				require.Equal(t, tt.expected, hex.EncodeToString(b))
			} else {
				require.Equal(t, tt.expected, string(b))
			}
		})
	}
}

// TestUnmarshal tests the unmarshal() internal function.
// unmarshal() tries SSZ first (if the type implements ssz.Unmarshaler),
// falling back to JSON when SSZ fails and the data starts with '{'.
func TestUnmarshal(t *testing.T) {
	// adZeros is a zero-valued AttestationData with non-nil Source/Target (required for valid SSZ).
	adZeros := AttestationData{
		Data: eth2p0.AttestationData{
			Source: new(eth2p0.Checkpoint),
			Target: new(eth2p0.Checkpoint),
		},
	}

	// adValid is an AttestationData with non-zero fields, including CommitteeLength > 0
	// so that JSON roundtrip validation succeeds.
	adValid := AttestationData{
		Data: eth2p0.AttestationData{
			Slot:   10,
			Index:  2,
			Source: new(eth2p0.Checkpoint),
			Target: new(eth2p0.Checkpoint),
		},
		Duty: eth2v1.AttesterDuty{
			Slot:                    10,
			CommitteeIndex:          2,
			CommitteeLength:         128,
			CommitteesAtSlot:        1,
			ValidatorCommitteeIndex: 5,
		},
	}

	adZerosSSZ, err := adZeros.MarshalSSZ()
	require.NoError(t, err)

	adValidSSZ, err := adValid.MarshalSSZ()
	require.NoError(t, err)

	adValidJSON, err := json.Marshal(adValid)
	require.NoError(t, err)

	sigBytes := Signature{0xde, 0xad, 0xbe, 0xef}
	sigJSON, err := json.Marshal(sigBytes)
	require.NoError(t, err)

	tests := []struct {
		name        string
		data        []byte
		target      func() any
		check       func(t *testing.T, got any)
		errContains string // non-empty → expect error containing this string
	}{
		{
			name:   "attestation_data_zeros/ssz",
			data:   adZerosSSZ,
			target: func() any { return new(AttestationData) },
			check: func(t *testing.T, got any) {
				t.Helper()
				require.Equal(t, adZeros, *got.(*AttestationData))
			},
		},
		{
			name:   "attestation_data_nozero/ssz",
			data:   adValidSSZ,
			target: func() any { return new(AttestationData) },
			check: func(t *testing.T, got any) {
				t.Helper()
				require.Equal(t, adValid, *got.(*AttestationData))
			},
		},
		{
			name:   "signature/json",
			data:   sigJSON,
			target: func() any { return new(Signature) },
			check: func(t *testing.T, got any) {
				t.Helper()
				require.Equal(t, sigBytes, *got.(*Signature))
			},
		},
		{
			// SSZ type falls back to JSON when SSZ unmarshal fails and data starts with '{'.
			name:   "attestation_data/json_fallback",
			data:   adValidJSON,
			target: func() any { return new(AttestationData) },
			check: func(t *testing.T, got any) {
				t.Helper()
				require.Equal(t, adValid, *got.(*AttestationData))
			},
		},
		{
			// Non-JSON, non-SSZ bytes produce an SSZ error (no JSON fallback attempted).
			name:        "error/invalid_ssz_no_json_prefix",
			data:        []byte{0x01, 0x02, 0x03},
			target:      func() any { return new(AttestationData) },
			errContains: "unmarshal ssz",
		},
		{
			// Invalid JSON for a non-SSZ type produces a JSON error.
			name:        "error/invalid_json_for_json_type",
			data:        []byte(`not-json`),
			target:      func() any { return new(Signature) },
			errContains: "unmarshal json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := tt.target()
			err := unmarshal(tt.data, v)

			if tt.errContains != "" {
				require.ErrorContains(t, err, tt.errContains)
				return
			}

			require.NoError(t, err)
			tt.check(t, v)
		})
	}
}
