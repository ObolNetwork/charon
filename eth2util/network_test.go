// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2util_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util"
)

var (
	invalidForkVersion = []byte{1, 0, 1, 0}
	invalidNetwork     = "invalidNetwork"
)

func TestForkVersionToChainID(t *testing.T) {
	gnosisForkVersion, err := hex.DecodeString(strings.TrimPrefix(eth2util.Gnosis.GenesisForkVersionHex, "0x"))
	require.NoError(t, err)

	chainID, err := eth2util.ForkVersionToChainID(gnosisForkVersion)
	require.NoError(t, err)
	require.Equal(t, chainID, uint64(100))

	chainID, err = eth2util.ForkVersionToChainID(invalidForkVersion)
	require.Error(t, err)
	require.ErrorContains(t, err, "invalid fork version")
	require.Equal(t, chainID, uint64(0))
}

func TestForkVersionToNetwork(t *testing.T) {
	sepoliaForkVersion, err := hex.DecodeString(strings.TrimPrefix(eth2util.Sepolia.GenesisForkVersionHex, "0x"))
	require.NoError(t, err)

	network, err := eth2util.ForkVersionToNetwork(sepoliaForkVersion)
	require.NoError(t, err)
	require.Equal(t, network, eth2util.Sepolia.Name)

	network, err = eth2util.ForkVersionToNetwork(invalidForkVersion)
	require.Error(t, err)
	require.ErrorContains(t, err, "invalid fork version")
	require.Equal(t, network, "")
}

func TestNetworkToForkVersion(t *testing.T) {
	fv, err := eth2util.NetworkToForkVersion(eth2util.Sepolia.Name)
	require.NoError(t, err)
	require.Equal(t, fv, eth2util.Sepolia.GenesisForkVersionHex)

	fv, err = eth2util.NetworkToForkVersion(invalidNetwork)
	require.Error(t, err)
	require.ErrorContains(t, err, "invalid network name")
	require.Equal(t, fv, "")
}

func TestNetworkToForkVersionBytes(t *testing.T) {
	sepoliaForkVersion, err := hex.DecodeString(strings.TrimPrefix(eth2util.Sepolia.GenesisForkVersionHex, "0x"))
	require.NoError(t, err)

	fv, err := eth2util.NetworkToForkVersionBytes(eth2util.Sepolia.Name)
	require.NoError(t, err)
	require.Equal(t, fv, sepoliaForkVersion)

	_, err = eth2util.NetworkToForkVersionBytes(invalidNetwork)
	require.Error(t, err)
	require.ErrorContains(t, err, "invalid network name")
}

func TestValidNetwork(t *testing.T) {
	supportedNetworks := []string{
		"mainnet",
		"goerli",
		"sepolia",
		"holesky",
		"gnosis",
		"chiado",
	}

	unsupportedNetworks := []string{
		"ropsten",
	}

	for _, network := range supportedNetworks {
		t.Run("supported network "+network, func(t *testing.T) {
			require.True(t, eth2util.ValidNetwork(network))
		})
	}

	for _, network := range unsupportedNetworks {
		t.Run("unsupported network "+network, func(t *testing.T) {
			require.False(t, eth2util.ValidNetwork(network))
		})
	}
}
