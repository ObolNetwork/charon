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
	inputCh     <-chan string
	outputCh    chan<- string
}

// NewCluster creates a new Byzantine cluster configuration.
func NewCluster(nodes, threshold uint, inputCh <-chan string, outputCh chan<- string) (*Cluster, error) {
	publicKeys := make([]*k1.PublicKey, 0)
	privateKeys := make([]*k1.PrivateKey, 0)

	for i := 0; i < int(nodes); i++ {
		privKey, err := k1.GeneratePrivateKey()
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate private key")
		}

		pubKey := privKey.PubKey()
		publicKeys = append(publicKeys, pubKey)
		privateKeys = append(privateKeys, privKey)
	}

	return &Cluster{
		nodes,
		threshold,
		publicKeys,
		privateKeys,
		inputCh,
		outputCh,
	}, nil
}

// ValidID returns true if the given ID is within the valid range.
func (c *Cluster) ValidID(id ID) bool {
	return id >= 1 && id <= ID(c.nodes)
}

// Leader returns the deterministic leader ID for the given view.
func (c *Cluster) Leader(view View) ID {
	return ID(uint64(view) % uint64(c.nodes))
}

// HasQuorum returns true if the given public keys meet the threshold.
func (c *Cluster) HasQuorum(pubKeys []*k1.PublicKey) bool {
	for _, pubKey := range pubKeys {
		found := false
		for _, clusterPubKey := range c.publicKeys {
			if clusterPubKey.IsEqual(pubKey) {
				found = true
				break
			}
		}

		if !found {
			return false
		}
	}

	return len(pubKeys) >= int(c.threshold)
}
