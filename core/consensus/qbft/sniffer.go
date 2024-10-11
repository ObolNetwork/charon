// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package qbft

import (
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
)

// newSniffer returns a new sniffer.
func newSniffer(nodes, peerIdx int64) *sniffer {
	return &sniffer{
		nodes:     nodes,
		peerIdx:   peerIdx,
		startedAt: time.Now(),
	}
}

// sniffer buffers consensus messages.
type sniffer struct {
	nodes     int64
	peerIdx   int64
	startedAt time.Time

	mu   sync.Mutex
	msgs []*pbv1.SniffedConsensusMsg
}

// Add adds a message to the sniffer buffer.
func (c *sniffer) Add(msg *pbv1.ConsensusMsg) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.msgs = append(c.msgs, &pbv1.SniffedConsensusMsg{
		Timestamp: timestamppb.Now(),
		Msg:       msg,
	})
}

// Instance returns the buffered messages as an instance.
func (c *sniffer) Instance() *pbv1.SniffedConsensusInstance {
	c.mu.Lock()
	defer c.mu.Unlock()

	return &pbv1.SniffedConsensusInstance{
		Nodes:     c.nodes,
		PeerIdx:   c.peerIdx,
		StartedAt: timestamppb.New(c.startedAt),
		Msgs:      c.msgs,
	}
}
