// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

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
	gnosisForkVersion, err := hex.DecodeString(strings.TrimPrefix(eth2util.Gnosis.ForkVersionHex, "0x"))
	require.NoError(t, err)

	chainID, err := eth2util.ForkVersionToChainID(gnosisForkVersion)
	require.NoError(t, err)
	require.Equal(t, chainID, int64(100))

	chainID, err = eth2util.ForkVersionToChainID(invalidForkVersion)
	require.Error(t, err)
	require.ErrorContains(t, err, "invalid fork version")
	require.Equal(t, chainID, int64(0))
}

func TestForkVersionToNetwork(t *testing.T) {
	sepoliaForkVersion, err := hex.DecodeString(strings.TrimPrefix(eth2util.Sepolia.ForkVersionHex, "0x"))
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
	require.Equal(t, fv, eth2util.Sepolia.ForkVersionHex)

	fv, err = eth2util.NetworkToForkVersion(invalidNetwork)
	require.Error(t, err)
	require.ErrorContains(t, err, "invalid network name")
	require.Equal(t, fv, "")
}

func TestNetworkToForkVersionBytes(t *testing.T) {
	sepoliaForkVersion, err := hex.DecodeString(strings.TrimPrefix(eth2util.Sepolia.ForkVersionHex, "0x"))
	require.NoError(t, err)

	fv, err := eth2util.NetworkToForkVersionBytes(eth2util.Sepolia.Name)
	require.NoError(t, err)
	require.Equal(t, fv, sepoliaForkVersion)

	_, err = eth2util.NetworkToForkVersionBytes(invalidNetwork)
	require.Error(t, err)
	require.ErrorContains(t, err, "invalid network name")
}
