// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2util_test

import (
	"encoding/hex"
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
