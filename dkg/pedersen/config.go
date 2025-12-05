// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pedersen

import (
	"time"

	kbls "github.com/drand/kyber-bls12381"
	kdkg "github.com/drand/kyber/share/dkg"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/cluster"
)

var DefaultSuite = kbls.NewBLS12381Suite().G1().(kdkg.Suite)

// Config holds the immutable configuration for the Pedersen DKG protocol.
type Config struct {
	Suite         kdkg.Suite
	ThisPeerID    peer.ID
	PeerMap       map[peer.ID]cluster.NodeIdx
	Threshold     int
	SessionID     []byte
	PhaseDuration time.Duration
	Reshare       *ReshareConfig
}

type ReshareConfig struct {
	TotalShares  int
	NewThreshold int
	AddedPeers   []peer.ID // Nodes being added to the cluster
	RemovedPeers []peer.ID // Nodes being removed from the cluster
}

// NewReshareConfig creates a new ReshareConfig instance.
func NewReshareConfig(totalShares, newThreshold int, addedPeers, removedPeers []peer.ID) *ReshareConfig {
	return &ReshareConfig{
		TotalShares:  totalShares,
		NewThreshold: newThreshold,
		AddedPeers:   addedPeers,
		RemovedPeers: removedPeers,
	}
}

// NewConfig creates a new Config instance for BLS12-381.
func NewConfig(thisPeerID peer.ID, peerMap map[peer.ID]cluster.NodeIdx, threshold int, sessionID []byte, phaseDuration time.Duration, reshare *ReshareConfig) *Config {
	return &Config{
		PhaseDuration: phaseDuration,
		Suite:         DefaultSuite,
		ThisPeerID:    thisPeerID,
		PeerMap:       peerMap,
		Threshold:     threshold,
		SessionID:     sessionID,
		Reshare:       reshare,
	}
}

func (c Config) Nodes() int {
	return len(c.PeerMap)
}

func (c Config) ThisNodeIndex() (int, error) {
	i, ok := c.PeerMap[c.ThisPeerID]
	if !ok {
		return 0, errors.New("this node is not in the peer map")
	}

	return i.PeerIdx, nil
}
