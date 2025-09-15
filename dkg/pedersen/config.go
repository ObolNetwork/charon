// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pedersen

import (
	kbls "github.com/drand/kyber-bls12381"
	kdkg "github.com/drand/kyber/share/dkg"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/obolnetwork/charon/cluster"
)

// Config holds the immutable configuration for the Pedersen DKG protocol.
type Config struct {
	Suite      kdkg.Suite
	ThisPeerID peer.ID
	PeerMap    map[peer.ID]cluster.NodeIdx
	Threshold  int
	SessionID  []byte
}

// NewConfig creates a new Config instance for BLS12-381.
func NewConfig(thisPeerID peer.ID, peerMap map[peer.ID]cluster.NodeIdx, threshold int, sessionID []byte) *Config {
	return &Config{
		Suite:      kbls.NewBLS12381Suite().G1().(kdkg.Suite),
		ThisPeerID: thisPeerID,
		PeerMap:    peerMap,
		Threshold:  threshold,
		SessionID:  sessionID,
	}
}

func (c Config) Nodes() int {
	return len(c.PeerMap)
}
