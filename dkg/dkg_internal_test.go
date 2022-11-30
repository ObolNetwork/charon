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
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

func TestInvalidSignatures(t *testing.T) {
	const (
		n  = 4
		th = 3
	)
	tss, sks, err := tbls.GenerateTSS(th, n, rand.Reader)
	require.NoError(t, err)

	shares := share{
		PubKey:       tss.PublicKey(),
		SecretShare:  sks[0],
		PublicShares: tss.PublicShares(),
	}

	getSigs := func(msg []byte) []core.ParSignedData {
		var sigs []core.ParSignedData
		for i := 0; i < n-1; i++ {
			sk, err := tblsconv.ShareToSecret(sks[i])
			require.NoError(t, err)

			sig, err := tbls.Sign(sk, msg)
			require.NoError(t, err)

			sigs = append(sigs, core.NewPartialSignature(tblsconv.SigToCore(sig), i+1))
		}

		sk, err := tblsconv.ShareToSecret(sks[n-1])
		require.NoError(t, err)

		invalidSig, err := tbls.Sign(sk, []byte("invalid msg"))
		require.NoError(t, err)

		sigs = append(sigs, core.NewPartialSignature(tblsconv.SigToCore(invalidSig), n))

		return sigs
	}

	pubkey, err := tblsconv.KeyToCore(tss.PublicKey())
	require.NoError(t, err)

	// Aggregate and verify deposit data signatures
	depositDataMsg := []byte("deposit data msg")

	_, err = aggDepositDataSigs(map[core.PubKey][]core.ParSignedData{pubkey: getSigs(depositDataMsg)}, []share{shares},
		map[core.PubKey][]byte{pubkey: depositDataMsg})
	require.EqualError(t, err, "invalid deposit data partial signature from peer")

	// Aggregate and verify cluster lock hash signatures
	lockMsg := []byte("cluster lock hash")

	_, _, err = aggLockHashSig(map[core.PubKey][]core.ParSignedData{pubkey: getSigs(lockMsg)}, map[core.PubKey]share{pubkey: shares}, lockMsg)
	require.EqualError(t, err, "invalid lock hash partial signature from peer")
}

func TestSyncProtocol(t *testing.T) {
}
