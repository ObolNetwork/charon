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

package deposit

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil"
)

var (
	depositDataFile = path.Join("testdata", "TestDepositData.golden")
	privKey         = "07e0355752a16fdc473d01676f7f82594991ea830eea928d8e2254dfd98d4beb"
	withdrawalAddr  = "0xc0404ed740a69d11201f5ed297c5732f562c6e4e"
	network         = "prater"
)

func TestDepositData(t *testing.T) {
	depositData, err := DepositDataFromFile(t, depositDataFile)
	require.NoError(t, err)

	// Check pubkeys
	privKeyBytes, err := hex.DecodeString(privKey)
	require.NoError(t, err)
	sk, err := tblsconv.SecretFromBytes(privKeyBytes)
	require.NoError(t, err)
	pk, err := sk.GetPublicKey()
	require.NoError(t, err)
	pubkey, err := tblsconv.KeyToETH2(pk)
	require.NoError(t, err)

	expectedPkBytes, err := hex.DecodeString(depositData.PubKey)
	require.NoError(t, err)
	var expectedPubkey eth2p0.BLSPubKey
	copy(expectedPubkey[:], expectedPkBytes)

	require.Equal(t, expectedPubkey, pubkey)

	creds, err := withdrawalCredsFromAddr(withdrawalAddr)
	require.NoError(t, err)

	forkVersion := networkToForkVersion(network)

	// Check deposit message root
	msgRoot, msgSigningRoot, err := GetMessageRoot(pubkey, creds, forkVersion)
	require.NoError(t, err)

	expectedMsgRootBytes, err := hex.DecodeString(depositData.DepositMessageRoot)
	require.NoError(t, err)

	assert.Equal(t, expectedMsgRootBytes, msgRoot[:])

	// check signature
	blsScheme := bls_sig.NewSigEth2()
	s, err := blsScheme.Sign(sk, msgSigningRoot[:])
	require.NoError(t, err)
	sigBytes, err := s.MarshalBinary()
	require.NoError(t, err)
	sig := hex.EncodeToString(sigBytes)

	require.Equal(t, depositData.Signature, sig)

	// check deposit data root
	sig2 := tblsconv.SigToETH2(s)
	depositDataRoot, _, err := GetDataRoot(pubkey, creds, sig2, forkVersion)
	require.NoError(t, err)

	expectedDepositDataBytes, err := hex.DecodeString(depositData.DepositDataRoot)
	require.NoError(t, err)

	require.Equal(t, expectedDepositDataBytes, depositDataRoot[:])

	// finally, check if serialized versions match.
	serializedDepositData, err := NewDepositData(pubkey, withdrawalAddr, sig2, network)
	require.NoError(t, err)

	testutil.RequireGoldenBytes(t, serializedDepositData)
}

func TestWithdrawalCredentials(t *testing.T) {
	depositData, err := DepositDataFromFile(t, depositDataFile)
	require.NoError(t, err)

	creds, err := withdrawalCredsFromAddr(withdrawalAddr)
	require.NoError(t, err)

	credsHex := hex.EncodeToString(creds[:])

	require.Equal(t, depositData.WithdrawalCredentials, credsHex)
}

func TestForkVersion(t *testing.T) {
	depositData, err := DepositDataFromFile(t, depositDataFile)
	require.NoError(t, err)

	fv, err := hex.DecodeString(depositData.ForkVersion)
	require.NoError(t, err)

	var forkVersionExpected eth2p0.Version
	copy(forkVersionExpected[:], fv)

	forkVersionGot := networkToForkVersion(network)

	assert.Equal(t, forkVersionExpected, forkVersionGot)
	assert.Equal(t, depositData.NetworkName, network)
}

func DepositDataFromFile(t *testing.T, filename string) (ddJSON, error) {
	t.Helper()

	expectedBytes, err := os.ReadFile(filename)
	require.NoError(t, err)

	var d ddJSON
	err = json.Unmarshal(expectedBytes, &d)
	if err != nil {
		return ddJSON{}, errors.Wrap(err, "read deposit data from file")
	}

	return d, nil
}
