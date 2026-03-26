// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2util

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestForkDataTypeHashTreeRoot(t *testing.T) {
	tests := []struct {
		name     string
		input    forkDataType
		expected string
	}{
		{
			name:     "zeros",
			input:    forkDataType{},
			expected: "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
		},
		{
			name: "version_only",
			input: forkDataType{
				CurrentVersion: [4]byte{0x01, 0x02, 0x03, 0x04},
			},
			expected: "ffd2fc34e5796a643f749b0b2b908c4ca3ce58ce24a00c49329a2dc0b54e47c6",
		},
		{
			name: "both_set",
			input: forkDataType{
				CurrentVersion: [4]byte{0xAB, 0xCD, 0xEF, 0x01},
				GenesisValidatorsRoot: [32]byte{
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
					0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
					0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
					0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
				},
			},
			expected: "7814fe240599c38bbd9899a02e477beb8c20c9e02ca29ba048f3d9eacb84e658",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.input.HashTreeRoot()
			require.NoError(t, err)
			require.Equal(t, tt.expected, hex.EncodeToString(got[:]))
		})
	}
}
