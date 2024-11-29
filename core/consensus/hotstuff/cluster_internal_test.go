// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff

import (
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"

	hs "github.com/obolnetwork/charon/core/hotstuff"
)

func TestThreshold(t *testing.T) {
	c := newCluster(4, nil, nil)

	require.Equal(t, uint(3), c.Threshold())
}

func TestHasQuorum(t *testing.T) {
	privKeys, pubKeys := generateClusterKeys(t, 4)
	c := newCluster(4, privKeys[0], pubKeys)

	t.Run("no quorum", func(t *testing.T) {
		pks := make([]*k1.PublicKey, 0)
		pks = append(pks, pubKeys[0], pubKeys[2])

		require.False(t, c.HasQuorum([]*k1.PublicKey{}))
		require.False(t, c.HasQuorum(pks))
	})

	t.Run("has quorum", func(t *testing.T) {
		pks := make([]*k1.PublicKey, 0)
		pks = append(pks, pubKeys[0], pubKeys[2], pubKeys[1])
		require.True(t, c.HasQuorum(pks))

		pks = append(pks, pubKeys[3])
		require.True(t, c.HasQuorum(pks))
	})
}

func TestLeader(t *testing.T) {
	c := newCluster(4, nil, nil)

	require.Equal(t, hs.ID(1), c.Leader(1))
	require.Equal(t, hs.ID(2), c.Leader(2))
	require.Equal(t, hs.ID(3), c.Leader(3))
	require.Equal(t, hs.ID(0), c.Leader(4))
	require.Equal(t, hs.ID(1), c.Leader(5))
	require.Equal(t, hs.ID(2), c.Leader(6))
	require.Equal(t, hs.ID(3), c.Leader(7))
}

func TestReplicaIDByPublicKey(t *testing.T) {
	privKeys, pubKeys := generateClusterKeys(t, 4)
	c := newCluster(4, privKeys[0], pubKeys)

	pubKey := pubKeys[1]
	id, err := c.PublicKeyToID(pubKey)
	require.NoError(t, err)
	require.Equal(t, hs.ID(1), id)

	pubKey = pubKeys[3]
	id, err = c.PublicKeyToID(pubKey)
	require.NoError(t, err)
	require.Equal(t, hs.ID(3), id)
}

func generateClusterKeys(t *testing.T, nodes uint) ([]*k1.PrivateKey, []*k1.PublicKey) {
	t.Helper()

	publicKeys := make([]*k1.PublicKey, 0)
	privateKeys := make([]*k1.PrivateKey, 0)

	for i := 0; i < int(nodes); i++ {
		privKey, err := k1.GeneratePrivateKey()
		require.NoError(t, err)

		pubKey := privKey.PubKey()
		publicKeys = append(publicKeys, pubKey)
		privateKeys = append(privateKeys, privKey)
	}

	return privateKeys, publicKeys
}
