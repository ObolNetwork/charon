// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/dkg/pedersen"
	"github.com/obolnetwork/charon/tbls"
)

func TestCopyToShares(t *testing.T) {
	pedersenShares := []*pedersen.Share{
		{
			PubKey:       randomPubKey(t),
			SecretShare:  randomPrivKey(t),
			PublicShares: map[int]tbls.PublicKey{0: randomPubKey(t), 1: randomPubKey(t)},
		},
		{
			PubKey:       randomPubKey(t),
			SecretShare:  randomPrivKey(t),
			PublicShares: map[int]tbls.PublicKey{0: randomPubKey(t), 1: randomPubKey(t)},
		},
	}

	out := copyToShares(pedersenShares)
	require.Len(t, out, len(pedersenShares))

	for i := range pedersenShares {
		require.Equal(t, pedersenShares[i].PubKey, out[i].PubKey)
		require.Equal(t, pedersenShares[i].SecretShare, out[i].SecretShare)
		require.Equal(t, pedersenShares[i].PublicShares, out[i].PublicShares)
	}
}

func randomPubKey(t *testing.T) tbls.PublicKey {
	t.Helper()

	var pubKey tbls.PublicKey

	_, err := rand.Read(pubKey[:])
	require.NoError(t, err)

	return pubKey
}

func randomPrivKey(t *testing.T) tbls.PrivateKey {
	t.Helper()

	var privKey tbls.PrivateKey

	_, err := rand.Read(privKey[:])
	require.NoError(t, err)

	return privKey
}
