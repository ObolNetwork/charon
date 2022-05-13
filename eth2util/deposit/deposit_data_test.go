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
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util/deposit"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil"
)

var (
	privKey        = "07e0355752a16fdc473d01676f7f82594991ea830eea928d8e2254dfd98d4beb"
	withdrawalAddr = "0xc0404ed740a69d11201f5ed297c5732f562c6e4e"
	network        = "prater"
)

func TestDepositData(t *testing.T) {
	// Get the pubkey
	privKeyBytes, err := hex.DecodeString(privKey)
	require.NoError(t, err)
	sk, err := tblsconv.SecretFromBytes(privKeyBytes)
	require.NoError(t, err)
	pk, err := sk.GetPublicKey()
	require.NoError(t, err)

	pubkey, err := tblsconv.KeyToETH2(pk)
	require.NoError(t, err)

	// Get deposit message root
	msgRoot, err := deposit.GetMessageRoot(pubkey, withdrawalAddr)
	require.NoError(t, err)

	forkVersion := eth2p0.Version([4]byte{0x00, 0x00, 0x10, 0x20})
	msgSigningRoot, err := deposit.GetSigningRoot(forkVersion, msgRoot)
	require.NoError(t, err)

	// sign the message signing root
	blsScheme := bls_sig.NewSigEth2()
	s, err := blsScheme.Sign(sk, msgSigningRoot[:])
	require.NoError(t, err)

	sigEth2 := tblsconv.SigToETH2(s)

	// check if serialized versions match.
	serializedDepositData, err := deposit.MarshalDepositData(pubkey, withdrawalAddr, sigEth2, network)
	require.NoError(t, err)

	testutil.RequireGoldenBytes(t, serializedDepositData)
}
