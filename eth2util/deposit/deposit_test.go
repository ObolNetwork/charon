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
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util/deposit"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

const (
	// Test output file and it's input values.
	testfile       = "testdata/deposit_data.json"
	privKey        = "07e0355752a16fdc473d01676f7f82594991ea830eea928d8e2254dfd98d4beb"
	withdrawalAddr = "0xc0404ed740a69d11201f5ed297c5732f562c6e4e"
	network        = "prater"
)

func TestDepositData(t *testing.T) {
	// Get the private and public keys
	privKeyBytes, err := hex.DecodeString(privKey)
	require.NoError(t, err)
	sk, err := tblsconv.SecretFromBytes(privKeyBytes)
	require.NoError(t, err)
	pk, err := sk.GetPublicKey()
	require.NoError(t, err)
	pubkey, err := tblsconv.KeyToETH2(pk)
	require.NoError(t, err)

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
	expected, err := os.ReadFile(testfile)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
}
