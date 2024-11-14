// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff

import (
	"math"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	hs "github.com/obolnetwork/charon/core/hotstuff"
)

// Represents immutable Byzantine cluster configuration.
type cluster struct {
	nodes       uint
	threshold   uint
	privateKey  *k1.PrivateKey
	publicKeys  []*k1.PublicKey
	pubKeysToID map[k1.PublicKey]hs.ID
}

var _ hs.Cluster = (*cluster)(nil)

// newCluster creates a new Byzantine cluster configuration.
func newCluster(nodes uint, privateKey *k1.PrivateKey, publicKeys []*k1.PublicKey) *cluster {
	pubKeysToID := make(map[k1.PublicKey]hs.ID)
	for i, pubKey := range publicKeys {
		pubKeysToID[*pubKey] = hs.NewIDFromIndex(i)
	}

	threshold := uint(math.Ceil(float64(nodes*2) / 3))

	return &cluster{
		nodes,
		threshold,
		privateKey,
		publicKeys,
		pubKeysToID,
	}
}

func (c *cluster) Leader(view hs.View) hs.ID {
	return hs.ID(1 + uint64(view)%uint64(c.nodes))
}

func (c *cluster) PublicKeyToID(pubKey *k1.PublicKey) hs.ID {
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
