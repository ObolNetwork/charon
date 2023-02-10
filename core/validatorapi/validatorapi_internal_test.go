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
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	tblsv2 "github.com/obolnetwork/charon/tbls/v2"
	"github.com/obolnetwork/charon/testutil"
)

func TestMismatchKeysFunc(t *testing.T) {
	const shareIdx = 1

	// Create keys (just use normal keys, not split tbls)
	secret, err := tblsv2.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tblsv2.SecretToPublicKey(secret)
	require.NoError(t, err)

	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)
	eth2Pubkey := eth2p0.BLSPubKey(pubkey)

	t.Run("no mismatch", func(t *testing.T) {
		allPubSharesByKey := map[core.PubKey]map[int]tblsv2.PublicKey{corePubKey: {shareIdx: pubkey}} // Maps self to self since not tbls

		vapi, err := NewComponent(nil, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
		require.NoError(t, err)
		pk, err := vapi.getPubKeyFunc(eth2Pubkey)
		require.NoError(t, err)
		require.Equal(t, eth2Pubkey, pk)
	})

	t.Run("mismatch", func(t *testing.T) {
		// Create a mismatching key
		pkraw := testutil.RandomCorePubKey(t)
		pkb, err := pkraw.Bytes()
		require.NoError(t, err)

		pubshare := *(*tblsv2.PublicKey)(pkb)
		allPubSharesByKey := map[core.PubKey]map[int]tblsv2.PublicKey{corePubKey: {shareIdx: pubkey, shareIdx + 1: pubshare}}

		vapi, err := NewComponent(nil, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
		require.NoError(t, err)

		resp, err := vapi.getPubKeyFunc(eth2p0.BLSPubKey(pubshare)) // Ask for a mismatching key
		require.Error(t, err)
		require.Equal(t, resp, eth2p0.BLSPubKey{})
		require.ErrorContains(t, err, "mismatching validator client key share index, Mth key share submitted to Nth charon peer")
	})

	t.Run("unknown public key", func(t *testing.T) {
		// Create a mismatching key
		pk, err := tblsconv.KeyFromCore(testutil.RandomCorePubKey(t))
		require.NoError(t, err)
		pubshare, err := tblsconv.KeyToETH2(pk)
		require.NoError(t, err)
		allPubSharesByKey := map[core.PubKey]map[int]tblsv2.PublicKey{corePubKey: {shareIdx: pubkey}}

		vapi, err := NewComponent(nil, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
		require.NoError(t, err)

		_, err = vapi.getPubKeyFunc(pubshare) // Ask for a mismatching key
		require.Error(t, err)
		require.ErrorContains(t, err, "unknown public key")
	})
}
