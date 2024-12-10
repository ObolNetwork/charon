// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff

import (
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
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
	c := newCluster(7, nil, nil)

	t.Run("same duty, different views", func(t *testing.T) {
		duty := core.NewAttesterDuty(1)

		require.Equal(t, hs.ID(4), c.Leader(duty, 1))
		require.Equal(t, hs.ID(5), c.Leader(duty, 2))
		require.Equal(t, hs.ID(6), c.Leader(duty, 3))
		require.Equal(t, hs.ID(0), c.Leader(duty, 4))
		require.Equal(t, hs.ID(1), c.Leader(duty, 5))
		require.Equal(t, hs.ID(2), c.Leader(duty, 6))
		require.Equal(t, hs.ID(3), c.Leader(duty, 7))
		require.Equal(t, hs.ID(4), c.Leader(duty, 8))
	})

	t.Run("same slot and view, different duty", func(t *testing.T) {
		duty1 := core.NewAttesterDuty(1)
		duty2 := core.NewProposerDuty(1)

		require.NotEqual(t, c.Leader(duty1, 1), c.Leader(duty2, 1))
	})

	t.Run("different slot, same view and duty", func(t *testing.T) {
		duty1 := core.NewAttesterDuty(1)
		duty2 := core.NewAttesterDuty(2)

		require.NotEqual(t, c.Leader(duty1, 1), c.Leader(duty2, 1))
	})
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
