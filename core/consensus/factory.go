// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus

import (
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/p2p"
)

type consensusFactory struct {
	tcpNode     host.Host
	sender      *p2p.Sender
	peers       []p2p.Peer
	p2pKey      *k1.PrivateKey
	deadliner   core.Deadliner
	gaterFunc   core.DutyGaterFunc
	snifferFunc func(*pbv1.SniffedConsensusInstance)
}

// NewConsensusFactory creates a new consensus factory.
func NewConsensusFactory(tcpNode host.Host, sender *p2p.Sender, peers []p2p.Peer, p2pKey *k1.PrivateKey,
	deadliner core.Deadliner, gaterFunc core.DutyGaterFunc, snifferFunc func(*pbv1.SniffedConsensusInstance),
) core.ConsensusFactory {
	return &consensusFactory{
		tcpNode:     tcpNode,
		sender:      sender,
		peers:       peers,
		p2pKey:      p2pKey,
		deadliner:   deadliner,
		gaterFunc:   gaterFunc,
		snifferFunc: snifferFunc,
	}
}

// New creates a new consensus instance.
func (f *consensusFactory) New(protocol protocol.ID) (core.Consensus, error) {
	// TODO: Refactor to a switch statement when more protocols are added.
	if protocol == QBFTv2ProtocolID {
		return New(f.tcpNode, f.sender, f.peers, f.p2pKey, f.deadliner, f.gaterFunc, f.snifferFunc)
	}

	return nil, errors.New("unknown consensus protocol")
}
