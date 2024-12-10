// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff

import (
	"math"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
	hs "github.com/obolnetwork/charon/core/hotstuff"
)

const (
	maxView      hs.View       = 3
	phaseTimeout time.Duration = 3 * time.Second
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
		pubKeysToID[*pubKey] = hs.ID(i)
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

func (c *cluster) Leader(duty core.Duty, view hs.View) hs.ID {
	return hs.ID((duty.Slot + uint64(duty.Type) + uint64(view)) % uint64(c.nodes))
}

func (c *cluster) PublicKeyToID(pubKey *k1.PublicKey) (hs.ID, error) {
	id, ok := c.pubKeysToID[*pubKey]
	if !ok {
		return 0, errors.New("public key not found")
	}

	return id, nil
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

func (*cluster) MaxView() hs.View {
	return maxView
}

func (*cluster) PhaseTimeout() time.Duration {
	return phaseTimeout
}
