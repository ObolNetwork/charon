// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff

import (
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

func TestHasQuorum(t *testing.T) {
	c, err := NewCluster(4, 3, nil, nil)
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
	c, err := NewCluster(4, 3, nil, nil)
	require.NoError(t, err)

	require.Equal(t, ID(1), c.Leader(1))
	require.Equal(t, ID(2), c.Leader(2))
	require.Equal(t, ID(3), c.Leader(3))
	require.Equal(t, ID(0), c.Leader(4))
	require.Equal(t, ID(1), c.Leader(5))
	require.Equal(t, ID(2), c.Leader(6))
	require.Equal(t, ID(3), c.Leader(7))
}

func TestValidID(t *testing.T) {
	c, err := NewCluster(4, 3, nil, nil)
	require.NoError(t, err)

	require.False(t, c.ValidID(0))
	require.True(t, c.ValidID(1))
	require.True(t, c.ValidID(2))
	require.True(t, c.ValidID(3))
	require.True(t, c.ValidID(4))
	require.False(t, c.ValidID(5))
}
