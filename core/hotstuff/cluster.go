// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff

import (
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/tbls"
)

// Represents the immutable Byzantine cluster configuration.
type Cluster struct {
	nodes       uint
	threshold   uint
	publicKey   tbls.PublicKey
	privateKeys map[ID]tbls.PrivateKey
	inputCh     <-chan string
	outputCh    chan<- string
}

// NewCluster creates a new Byzantine cluster configuration.
func NewCluster(nodes, threshold uint, inputCh <-chan string, outputCh chan<- string) (*Cluster, error) {
	privKey, err := tbls.GenerateSecretKey()
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate secret key")
	}

	pubKey, err := tbls.SecretToPublicKey(privKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert secret key to public key")
	}

	privKeysMap, err := tbls.ThresholdSplit(privKey, nodes, threshold)
	if err != nil {
		return nil, errors.Wrap(err, "failed to split secret key")
	}

	privKeysByID := make(map[ID]tbls.PrivateKey)
	for i, privKey := range privKeysMap {
		privKeysByID[ID(i)] = privKey
	}

	return &Cluster{
		nodes,
		threshold,
		pubKey,
		privKeysByID,
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
