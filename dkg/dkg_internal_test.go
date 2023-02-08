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

package dkg

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	tblsv2 "github.com/obolnetwork/charon/tbls/v2"
	tblsconv2 "github.com/obolnetwork/charon/tbls/v2/tblsconv"
)

func TestInvalidSignatures(t *testing.T) {
	const (
		n  = 4
		th = 3
	)

	secret, err := tblsv2.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tblsv2.SecretToPublicKey(secret)
	require.NoError(t, err)

	secretShares, err := tblsv2.ThresholdSplit(secret, n, th)
	require.NoError(t, err)

	pubshares := make(map[int]tblsv2.PublicKey)

	for idx, share := range secretShares {
		pubkey, err := tblsv2.SecretToPublicKey(share)
		require.NoError(t, err)

		pubshares[idx] = pubkey
	}

	shares := share{
		PubKey:       pubkey,
		SecretShare:  secretShares[0],
		PublicShares: pubshares,
	}

	getSigs := func(msg []byte) []core.ParSignedData {
		var sigs []core.ParSignedData
		for i := 0; i < n-1; i++ {
			sig, err := tblsv2.Sign(secretShares[i+1], msg)
			require.NoError(t, err)

			sigs = append(sigs, core.NewPartialSignature(tblsconv2.SigToCore(sig), i+1))
		}

		invalidSig, err := tblsv2.Sign(secretShares[n-1], []byte("invalid msg"))
		require.NoError(t, err)

		sigs = append(sigs, core.NewPartialSignature(tblsconv2.SigToCore(invalidSig), n))

		return sigs
	}

	corePubkey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)

	// Aggregate and verify deposit data signatures
	depositDataMsg := []byte("deposit data msg")

	_, err = aggDepositDataSigs(map[core.PubKey][]core.ParSignedData{corePubkey: getSigs(depositDataMsg)}, []share{shares},
		map[core.PubKey][]byte{corePubkey: depositDataMsg})
	require.EqualError(t, err, "invalid deposit data partial signature from peer")

	// Aggregate and verify cluster lock hash signatures
	lockMsg := []byte("cluster lock hash")

	_, _, err = aggLockHashSig(map[core.PubKey][]core.ParSignedData{corePubkey: getSigs(lockMsg)}, map[core.PubKey]share{corePubkey: shares}, lockMsg)
	require.EqualError(t, err, "invalid lock hash partial signature from peer: signature not verified")
}

func TestValidSignatures(t *testing.T) {
	const (
		n  = 4
		th = 3
	)

	secret, err := tblsv2.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tblsv2.SecretToPublicKey(secret)
	require.NoError(t, err)

	secretShares, err := tblsv2.ThresholdSplit(secret, n, th)
	require.NoError(t, err)

	pubshares := make(map[int]tblsv2.PublicKey)

	for idx, share := range secretShares {
		pubkey, err := tblsv2.SecretToPublicKey(share)
		require.NoError(t, err)

		pubshares[idx] = pubkey
	}

	shares := share{
		PubKey:       pubkey,
		SecretShare:  secret,
		PublicShares: pubshares,
	}

	getSigs := func(msg []byte) []core.ParSignedData {
		var sigs []core.ParSignedData
		for i := 0; i < n-1; i++ {
			pk := secretShares[i+1]
			sig, err := tblsv2.Sign(pk, msg)
			require.NoError(t, err)

			coreSig := tblsconv2.SigToCore(sig)
			sigs = append(sigs, core.NewPartialSignature(coreSig, i+1))
		}

		return sigs
	}

	corePubkey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)

	// Aggregate and verify deposit data signatures
	depositDataMsg := []byte("deposit data msg")

	_, err = aggDepositDataSigs(map[core.PubKey][]core.ParSignedData{corePubkey: getSigs(depositDataMsg)}, []share{shares},
		map[core.PubKey][]byte{corePubkey: depositDataMsg})
	require.NoError(t, err)

	// Aggregate and verify cluster lock hash signatures
	lockMsg := []byte("cluster lock hash")

	_, _, err = aggLockHashSig(map[core.PubKey][]core.ParSignedData{corePubkey: getSigs(lockMsg)}, map[core.PubKey]share{corePubkey: shares}, lockMsg)
	require.NoError(t, err)
}
