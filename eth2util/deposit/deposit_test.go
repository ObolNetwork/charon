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

package deposit_test

import (
	"encoding/hex"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util/deposit"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

const (
	// Test output file and it's input values.
	withdrawalAddr = "0xc0404ed740a69d11201f5ed297c5732f562c6e4e"
	network        = "prater"
)

func TestDepositData(t *testing.T) {
	file := "testdata/deposit-data.json"
	privKey := "07e0355752a16fdc473d01676f7f82594991ea830eea928d8e2254dfd98d4beb"

	sk, pubkey := GetKeys(t, privKey)

	// Get deposit message signing root
	msgSigningRoot, err := deposit.GetMessageSigningRoot(pubkey, withdrawalAddr, network)
	require.NoError(t, err)

	// Sign it
	s, err := tbls.Sign(sk, msgSigningRoot[:])
	require.NoError(t, err)
	sigEth2 := tblsconv.SigToETH2(s)

	// Check if serialized versions match.
	actual, err := deposit.MarshalDepositData(pubkey, withdrawalAddr, network, sigEth2)
	require.NoError(t, err)

	// Not using golden file since output MUST never change.
	expected, err := os.ReadFile(file)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
}

func TestMarshalDepositDatas(t *testing.T) {
	file := "testdata/deposit-datas.json"
	privKeys := []string{
		"01477d4bfbbcebe1fef8d4d6f624ecbb6e3178558bb1b0d6286c816c66842a6d",
		"5b77c0f0ef7c4ddc123d55b8bd93daeefbd7116764a941c0061a496649e145b5",
		"1dabcbfc9258f0f28606bf9e3b1c9f06d15a6e4eb0fbc28a43835eaaed7623fc",
		"002ff4fd29d3deb6de9f5d115182a49c618c97acaa365ad66a0b240bd825c4ff",
	}

	var depositDatas [][]byte

	for i := 0; i < len(privKeys); i++ {
		sk, pk := GetKeys(t, privKeys[i])

		msgRoot, err := deposit.GetMessageSigningRoot(pk, withdrawalAddr, network)
		require.NoError(t, err)

		sig, err := tbls.Sign(sk, msgRoot[:])
		require.NoError(t, err)

		sigEth2 := tblsconv.SigToETH2(sig)
		bytes, err := deposit.MarshalDepositData(pk, withdrawalAddr, network, sigEth2)
		require.NoError(t, err)

		depositDatas = append(depositDatas, bytes)
	}

	actual, err := deposit.MarshalDepositDatas(depositDatas)
	require.NoError(t, err)

	// Not using golden file since output MUST never change.
	expected, err := os.ReadFile(file)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
}

// Get the private and public keys in appropriate format for the test.
func GetKeys(t *testing.T, privKey string) (*bls_sig.SecretKey, eth2p0.BLSPubKey) {
	t.Helper()

	privKeyBytes, err := hex.DecodeString(privKey)
	require.NoError(t, err)

	sk, err := tblsconv.SecretFromBytes(privKeyBytes)
	require.NoError(t, err)

	pk, err := sk.GetPublicKey()
	require.NoError(t, err)

	pubkey, err := tblsconv.KeyToETH2(pk)
	require.NoError(t, err)

	return sk, pubkey
}
