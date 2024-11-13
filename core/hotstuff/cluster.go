// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff

import (
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/obolnetwork/charon/app/errors"
)

// Represents the immutable Byzantine cluster configuration.
type Cluster struct {
	nodes       uint
	threshold   uint
	publicKeys  []*k1.PublicKey
	privateKeys []*k1.PrivateKey
	pubKeysToID map[k1.PublicKey]ID
	inputCh     <-chan Value
	outputCh    chan<- Value
}

// NewCluster creates a new Byzantine cluster configuration.
func NewCluster(nodes, threshold uint, inputCh <-chan Value, outputCh chan<- Value) (*Cluster, error) {
	publicKeys := make([]*k1.PublicKey, 0)
	privateKeys := make([]*k1.PrivateKey, 0)
	pubKeysToID := make(map[k1.PublicKey]ID)

	for i := 0; i < int(nodes); i++ {
		privKey, err := k1.GeneratePrivateKey()
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate private key")
		}

		pubKey := privKey.PubKey()
		publicKeys = append(publicKeys, pubKey)
		privateKeys = append(privateKeys, privKey)

		pubKeysToID[*pubKey] = ID(i + 1)
	}

	return &Cluster{
		nodes,
		threshold,
		publicKeys,
		privateKeys,
		pubKeysToID,
		inputCh,
		outputCh,
	}, nil
}

// Leader returns the deterministic leader ID for the given view.
func (c *Cluster) Leader(view View) ID {
	return ID(uint64(view) % uint64(c.nodes))
}

// PublicKeyToID returns the replica ID for the given public key.
func (c *Cluster) PublicKeyToID(pubKey *k1.PublicKey) ID {
	return c.pubKeysToID[*pubKey]
}

// HasQuorum returns true if the given public keys meet the threshold.
func (c *Cluster) HasQuorum(pubKeys []*k1.PublicKey) bool {
	for _, pubKey := range pubKeys {
		_, ok := c.pubKeysToID[*pubKey]
		if !ok {
			return false
		}
	}

	return len(pubKeys) >= int(c.threshold)
}
