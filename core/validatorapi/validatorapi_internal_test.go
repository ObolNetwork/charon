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

package validatorapi

import (
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil"
)

func TestMismatchKeysFunc(t *testing.T) {
	// Create keys (just use normal keys, not split tbls)
	pubkey, _, err := tbls.Keygen()
	require.NoError(t, err)
	corePubKey, err := tblsconv.KeyToCore(pubkey)
	require.NoError(t, err)
	eth2Pubkey, err := tblsconv.KeyToETH2(pubkey)
	require.NoError(t, err)

	t.Run("no mismatch", func(t *testing.T) {
		pubShareByKey := map[*bls_sig.PublicKey]*bls_sig.PublicKey{pubkey: pubkey} // Maps self to self since not tbls
		pubshares := map[int]*bls_sig.PublicKey{1: pubkey}
		allPubSharesByKey := map[core.PubKey]map[int]*bls_sig.PublicKey{corePubKey: pubshares}

		vapi, err := NewComponent(nil, pubShareByKey, allPubSharesByKey, 0, "", false, nil)
		require.NoError(t, err)
		pk, err := vapi.getPubKeyFunc(eth2Pubkey)
		require.NoError(t, err)
		require.Equal(t, eth2Pubkey, pk)
	})

	t.Run("mismatch", func(t *testing.T) {
		// Create a mismatching key
		pk, err := tblsconv.KeyFromCore(testutil.RandomCorePubKey(t))
		require.NoError(t, err)
		eth2key, err := tblsconv.KeyToETH2(pk)
		require.NoError(t, err)

		pubShareByKey := map[*bls_sig.PublicKey]*bls_sig.PublicKey{pubkey: pubkey}
		pubshares := map[int]*bls_sig.PublicKey{1: pk}
		allPubSharesByKey := map[core.PubKey]map[int]*bls_sig.PublicKey{corePubKey: pubshares}

		vapi, err := NewComponent(nil, pubShareByKey, allPubSharesByKey, 0, "", false, nil)
		require.NoError(t, err)
		resp, err := vapi.getPubKeyFunc(eth2key)
		require.Error(t, err)
		require.Equal(t, resp, eth2p0.BLSPubKey{})
		require.ErrorContains(t, err, "mismatching validator client key share index, Mth key share submitted to Nth charon peer")
	})
}
