// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package validatorapi

import (
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil"
)

func TestMismatchKeysFunc(t *testing.T) {
	const shareIdx = 1

	// Create keys (just use normal keys, not split tbls)
	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)
	eth2Pubkey := eth2p0.BLSPubKey(pubkey)

	t.Run("no mismatch", func(t *testing.T) {
		allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey}} // Maps self to self since not tbls

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

		pubshare := *(*tbls.PublicKey)(pkb)
		allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey, shareIdx + 1: pubshare}}

		vapi, err := NewComponent(nil, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
		require.NoError(t, err)

		resp, err := vapi.getPubKeyFunc(eth2p0.BLSPubKey(pubshare)) // Ask for a mismatching key
		require.Error(t, err)
		require.Equal(t, resp, eth2p0.BLSPubKey{})
		require.ErrorContains(t, err, "mismatching validator client key share index, Mth key share submitted to Nth charon peer")
	})

	t.Run("unknown public key", func(t *testing.T) {
		// Create a mismatching key
		pkb, err := testutil.RandomCorePubKey(t).Bytes()
		require.NoError(t, err)
		pk, err := tblsconv.PubkeyFromBytes(pkb)
		require.NoError(t, err)
		pubshare := eth2p0.BLSPubKey(pk)
		allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey}}

		vapi, err := NewComponent(nil, allPubSharesByKey, shareIdx, nil, testutil.BuilderFalse, nil)
		require.NoError(t, err)

		_, err = vapi.getPubKeyFunc(pubshare) // Ask for a mismatching key
		require.Error(t, err)
		require.ErrorContains(t, err, "unknown public key")
	})
}

func TestWrapResponse(t *testing.T) {
	resp := wrapResponse(123)

	require.NotNil(t, resp)
	require.Equal(t, 123, resp.Data)
	require.Nil(t, resp.Metadata)
}

func TestWrapResponseWithMetadata(t *testing.T) {
	metadata := map[string]any{
		"foo": 123,
	}

	resp := wrapResponseWithMetadata(123, metadata)

	require.NotNil(t, resp)
	require.Equal(t, 123, resp.Data)
	require.Equal(t, metadata, resp.Metadata)
}
