// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2util_test

import (
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util"
)

func TestChecksummedAddress(t *testing.T) {
	// Test examples from https://eips.ethereum.org/EIPS/eip-55.
	addrs := []string{
		"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
		"0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
		"0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
		"0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
	}
	for _, addr := range addrs {
		t.Run(addr, func(t *testing.T) {
			checksummed, err := eth2util.ChecksumAddress(addr)
			require.NoError(t, err)
			require.Equal(t, addr, checksummed)

			checksummed, err = eth2util.ChecksumAddress(strings.ToLower(addr))
			require.NoError(t, err)
			require.Equal(t, addr, checksummed)

			checksummed, err = eth2util.ChecksumAddress("0x" + strings.ToUpper(addr[2:]))
			require.NoError(t, err)
			require.Equal(t, addr, checksummed)
		})
	}
}

func TestInvalidAddrs(t *testing.T) {
	addrs := []string{
		"0x0000000000000000000000000000000000dead",
		"0x00000000000000000000000000000000000000dead",
		"0x0000000000000000000000000000000000000bar",
		"000000000000000000000000000000000000dead",
	}
	for _, addr := range addrs {
		t.Run(addr, func(t *testing.T) {
			_, err := eth2util.ChecksumAddress(addr)
			require.Error(t, err)
		})
	}
}

func TestPublicKeyToAddress(t *testing.T) {
	// Test fixtures from geth/crypto package.
	const testAddrHex = "0x970E8128AB834E8EAC17Ab8E3812F010678CF791"
	const testPrivHex = "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032"

	b, err := hex.DecodeString(testPrivHex)
	require.NoError(t, err)

	privKey := k1.PrivKeyFromBytes(b)

	actual := eth2util.PublicKeyToAddress(privKey.PubKey())
	require.Equal(t, testAddrHex, actual)
}

func TestValidateBeaconNodeHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
		valid   bool
	}{
		{
			name:    "nil",
			headers: nil,
			valid:   true,
		},
		{
			name:    "one pair",
			headers: []string{"header-1=value-1"},
			valid:   true,
		},
		{
			name:    "two pairs",
			headers: []string{"header-1=value-1", "header-2=value-2"},
			valid:   true,
		},
		{
			name:    "empty",
			headers: []string{""},
			valid:   false,
		},
		{
			name:    "value missing",
			headers: []string{"header-1="},
			valid:   false,
		},
		{
			name:    "header missing",
			headers: []string{"=value-1"},
			valid:   false,
		},
		{
			name:    "extra comma end",
			headers: []string{"header-1=value-1,"},
			valid:   false,
		},
		{
			name:    "extra comma start",
			headers: []string{",header-1=value-1"},
			valid:   false,
		},
		{
			name:    "pair and value missing",
			headers: []string{"header-1=value-1", "header-2="},
			valid:   false,
		},
		{
			name:    "header and value missing 1",
			headers: []string{"=="},
			valid:   false,
		},
		{
			name:    "header and value missing 2",
			headers: []string{",,"},
			valid:   false,
		},
		{
			name:    "value contains equal sign",
			headers: []string{"Authorization=Basic bmljZXRyeQ=="},
			valid:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := eth2util.ValidateBeaconNodeHeaders(tt.headers)
			if err != nil && tt.valid {
				require.Fail(t, "Fail", "Header (%d) is invalid, want valid", tt.headers)
			} else if err == nil && !tt.valid {
				require.Fail(t, "Fail", "Header (%d) is valid, want invalid", tt.headers)
			}
		})
	}
}

func TestParseBeaconNodeHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
		want    map[string]string
	}{
		{
			name:    "nil",
			headers: nil,
			want:    map[string]string{},
		},
		{
			name:    "one pair",
			headers: []string{"header-1=value-1"},
			want:    map[string]string{"header-1": "value-1"},
		},
		{
			name:    "two pairs",
			headers: []string{"header-1=value-1", "header-2=value-2"},
			want:    map[string]string{"header-1": "value-1", "header-2": "value-2"},
		},
		{
			name:    "value contains equal sign",
			headers: []string{"Authorization=Basic bmljZXRyeQ=="},
			want:    map[string]string{"Authorization": "Basic bmljZXRyeQ=="},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := eth2util.ParseBeaconNodeHeaders(tt.headers)
			if err != nil {
				require.Fail(t, "Fail", "Header (%d) failed to parse", tt.headers)
			}
			if !reflect.DeepEqual(parsed, tt.want) {
				require.Fail(t, "Fail", "Headers badly parsed, have %v, want %v", parsed, tt.want)
			}
		})
	}
}
