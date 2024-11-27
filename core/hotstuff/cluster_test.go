// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff_test

import (
	"testing"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core/hotstuff"
)

func TestHasQuorum(t *testing.T) {
	c, err := newCluster(4, 3, 1, 100)
	require.NoError(t, err)

	pubKeys := make([]*k1.PublicKey, 0)
	pubKeys = append(pubKeys, c.publicKeys[0])
	pubKeys = append(pubKeys, c.publicKeys[2])

	require.False(t, c.HasQuorum([]*k1.PublicKey{}))
	require.False(t, c.HasQuorum(pubKeys))

	pubKeys = append(pubKeys, c.publicKeys[1])
	require.True(t, c.HasQuorum(pubKeys))

	pubKeys = append(pubKeys, c.publicKeys[3])
	require.True(t, c.HasQuorum(pubKeys))
}

func TestLeader(t *testing.T) {
	c, err := newCluster(7, 5, 1, 100)
	require.NoError(t, err)

	require.Equal(t, hotstuff.ID(2), c.Leader(1))
	require.Equal(t, hotstuff.ID(3), c.Leader(2))
	require.Equal(t, hotstuff.ID(4), c.Leader(3))
	require.Equal(t, hotstuff.ID(5), c.Leader(4))
	require.Equal(t, hotstuff.ID(6), c.Leader(5))
	require.Equal(t, hotstuff.ID(7), c.Leader(6))
	require.Equal(t, hotstuff.ID(1), c.Leader(7))
	require.Equal(t, hotstuff.ID(2), c.Leader(8))
}

func TestReplicaIDByPublicKey(t *testing.T) {
	c, err := newCluster(4, 3, 1, 100)
	require.NoError(t, err)

	pubKey := c.publicKeys[1]
	id := c.PublicKeyToID(pubKey)
	require.Equal(t, hotstuff.ID(2), id)

	pubKey = c.publicKeys[3]
	id = c.PublicKeyToID(pubKey)
	require.Equal(t, hotstuff.ID(4), id)
}

// Represents test cluster configuration.
type cluster struct {
	nodes          uint
	threshold      uint
	maxView        uint
	phaseTimeoutMs uint
	publicKeys     []*k1.PublicKey
	privateKeys    []*k1.PrivateKey
	pubKeysToID    map[k1.PublicKey]hotstuff.ID
}

var _ hotstuff.Cluster = (*cluster)(nil)

// NewCluster creates a new Byzantine cluster configuration.
func newCluster(nodes, threshold, maxView, phaseTimeoutMs uint) (*cluster, error) {
	publicKeys := make([]*k1.PublicKey, 0)
	privateKeys := make([]*k1.PrivateKey, 0)
	pubKeysToID := make(map[k1.PublicKey]hotstuff.ID)

	for i := 0; i < int(nodes); i++ {
		privKey, err := k1.GeneratePrivateKey()
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate private key")
		}

		pubKey := privKey.PubKey()
		publicKeys = append(publicKeys, pubKey)
		privateKeys = append(privateKeys, privKey)

		pubKeysToID[*pubKey] = hotstuff.NewIDFromIndex(i)
	}

	return &cluster{
		nodes,
		threshold,
		maxView,
		phaseTimeoutMs,
		publicKeys,
		privateKeys,
		pubKeysToID,
	}, nil
}

func (c *cluster) Leader(view hotstuff.View) hotstuff.ID {
	return hotstuff.ID(1 + uint64(view)%uint64(c.nodes))
}

func (c *cluster) PublicKeyToID(pubKey *k1.PublicKey) hotstuff.ID {
	return c.pubKeysToID[*pubKey]
}

func (c *cluster) HasQuorum(pubKeys []*k1.PublicKey) bool {
	for _, pubKey := range pubKeys {
		_, ok := c.pubKeysToID[*pubKey]
		if !ok {
			return false
		}
	}

	return len(pubKeys) >= int(c.threshold)
}

func (c *cluster) Threshold() uint {
	return c.threshold
}

func (c *cluster) MaxView() hotstuff.View {
	return hotstuff.View(c.maxView)
}

func (c *cluster) PhaseTimeout() time.Duration {
	return time.Duration(c.phaseTimeoutMs) * time.Millisecond
}
