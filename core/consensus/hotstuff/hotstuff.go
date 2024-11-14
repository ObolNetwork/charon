// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff

import (
	"context"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/protocol"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/consensus/metrics"
	"github.com/obolnetwork/charon/core/consensus/protocols"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/p2p"
)

type subscriber func(ctx context.Context, duty core.Duty, value proto.Message) error

// Consensus implements core.Consensus.
type Consensus struct {
	// Immutable state
	tcpNode   host.Host
	sender    *p2p.Sender
	peers     []p2p.Peer
	subs      []subscriber
	deadliner core.Deadliner
	metrics   metrics.ConsensusMetrics
	transport *transport
	cluster   *cluster
}

var _ core.Consensus = (*Consensus)(nil)

// NewConsensus returns a new consensus QBFT component.
func NewConsensus(tcpNode host.Host, sender *p2p.Sender, peers []p2p.Peer, p2pKey *k1.PrivateKey, deadliner core.Deadliner) *Consensus {
	keys := make([]*k1.PublicKey, len(peers))
	for i, p := range peers {
		pk, _ := p.PublicKey()
		keys[i] = pk
	}

	transport := newTransport(tcpNode, sender, peers)
	cluster := newCluster(uint(len(peers)), p2pKey, keys)

	return &Consensus{
		tcpNode:   tcpNode,
		sender:    sender,
		peers:     peers,
		deadliner: deadliner,
		metrics:   metrics.NewConsensusMetrics(protocols.HotStuffv1ProtocolID),
		transport: transport,
		cluster:   cluster,
	}
}

func (*Consensus) ProtocolID() protocol.ID {
	return protocols.HotStuffv1ProtocolID
}

func (c *Consensus) Start(ctx context.Context) {
	const logTopic = "hotstuff"

	p2p.RegisterHandler(logTopic, c.tcpNode,
		protocols.HotStuffv1ProtocolID,
		func() proto.Message { return new(pbv1.HotStuffMsg) },
		c.transport.P2PHandler)

	go func() {
		for {
			select {
			case <-ctx.Done():
				p2p.RegisterHandler(logTopic, c.tcpNode, protocols.HotStuffv1ProtocolID,
					func() proto.Message { return new(pbv1.HotStuffMsg) }, nil)

				return
			case <-c.deadliner.C():
				// TODO: remove duty
			}
		}
	}()
}

func (*Consensus) Participate(context.Context, core.Duty) error {
	panic("implement me")
}

func (*Consensus) Propose(context.Context, core.Duty, core.UnsignedDataSet) error {
	panic("implement me")
}

func (c *Consensus) Subscribe(fn func(context.Context, core.Duty, core.UnsignedDataSet) error) {
	c.subs = append(c.subs, func(ctx context.Context, duty core.Duty, value proto.Message) error {
		unsignedPB, ok := value.(*pbv1.UnsignedDataSet)
		if !ok {
			return nil
		}

		unsigned, err := core.UnsignedDataSetFromProto(duty.Type, unsignedPB)
		if err != nil {
			return err
		}

		return fn(ctx, duty, unsigned)
	})
}
