// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util"
)

func TestChecksumAddrs(t *testing.T) {
	// EIP-55 test vector address.
	const checksummed = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"

	tests := []struct {
		name        string
		addrs       []string
		network     string
		expected    []string
		expectedErr string
	}{
		{
			name:     "checksummed",
			addrs:    []string{checksummed},
			network:  eth2util.Mainnet.Name,
			expected: []string{checksummed},
		},
		{
			name:     "lowercase normalised",
			addrs:    []string{strings.ToLower(checksummed)},
			network:  eth2util.Mainnet.Name,
			expected: []string{checksummed},
		},
		{
			name:     "uppercase normalised",
			addrs:    []string{"0x" + strings.ToUpper(checksummed[2:])},
			network:  eth2util.Gnosis.Name,
			expected: []string{checksummed},
		},
		{
			name:        "mixed case bad checksum",
			addrs:       []string{"0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"},
			network:     eth2util.Hoodi.Name,
			expectedErr: "does not match its EIP-55 checksum",
		},
		{
			name:        "too short",
			addrs:       []string{"0xBAD000BAD000BAD"},
			network:     eth2util.Hoodi.Name,
			expectedErr: "invalid withdrawal address",
		},
		{
			name:        "no 0x prefix",
			addrs:       []string{checksummed[2:] + "00"},
			network:     eth2util.Hoodi.Name,
			expectedErr: "invalid withdrawal address",
		},
		{
			name:        "non hex",
			addrs:       []string{"0x" + strings.Repeat("zz", 20)},
			network:     eth2util.Hoodi.Name,
			expectedErr: "invalid withdrawal address",
		},
		{
			name:        "zero address mainnet",
			addrs:       []string{zeroAddress},
			network:     eth2util.Mainnet.Name,
			expectedErr: "zero withdrawal address forbidden on this network",
		},
		{
			name:        "zero address gnosis",
			addrs:       []string{checksummed, zeroAddress},
			network:     eth2util.Gnosis.Name,
			expectedErr: "zero withdrawal address forbidden on this network",
		},
		{
			name:     "zero address testnet",
			addrs:    []string{zeroAddress},
			network:  eth2util.Hoodi.Name,
			expected: []string{zeroAddress},
		},
		{
			name:     "zero address custom testnet",
			addrs:    []string{zeroAddress},
			network:  "",
			expected: []string{zeroAddress},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := checksumAddrs(t.Context(), test.addrs, "withdrawal", test.network, true)
			if test.expectedErr != "" {
				require.ErrorContains(t, err, test.expectedErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, test.expected, got)
		})
	}
}

func TestChecksumValidatorAddrs(t *testing.T) {
	const checksummed = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"

	ctx := t.Context()

	fee, wd, err := checksumValidatorAddrs(ctx, []string{strings.ToLower(checksummed)}, []string{strings.ToLower(checksummed)}, eth2util.Mainnet.Name, true)
	require.NoError(t, err)
	require.Equal(t, []string{checksummed}, fee)
	require.Equal(t, []string{checksummed}, wd)

	// A zero fee recipient only warns.
	fee, _, err = checksumValidatorAddrs(ctx, []string{zeroAddress}, []string{checksummed}, eth2util.Mainnet.Name, true)
	require.NoError(t, err)
	require.Equal(t, []string{zeroAddress}, fee)

	// A zero withdrawal address is rejected only when asked to.
	_, _, err = checksumValidatorAddrs(ctx, []string{checksummed}, []string{zeroAddress}, eth2util.Mainnet.Name, true)
	require.ErrorContains(t, err, "zero withdrawal address forbidden on this network")

	_, wd, err = checksumValidatorAddrs(ctx, []string{checksummed}, []string{zeroAddress}, eth2util.Gnosis.Name, false)
	require.NoError(t, err)
	require.Equal(t, []string{zeroAddress}, wd)

	_, _, err = checksumValidatorAddrs(ctx, []string{checksummed}, []string{"0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"}, eth2util.Mainnet.Name, true)
	require.ErrorContains(t, err, "invalid withdrawal address")
}
