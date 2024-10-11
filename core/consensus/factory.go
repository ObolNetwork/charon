// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus

import (
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/consensus/qbft"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/p2p"
)

type consensusFactory struct {
	tcpNode          host.Host
	sender           *p2p.Sender
	peers            []p2p.Peer
	p2pKey           *k1.PrivateKey
	deadliner        core.Deadliner
	gaterFunc        core.DutyGaterFunc
	snifferFunc      func(*pbv1.SniffedConsensusInstance)
	defaultConsensus core.Consensus
}

// NewConsensusFactory creates a new consensus factory with the default consensus protocol.
func NewConsensusFactory(tcpNode host.Host, sender *p2p.Sender, peers []p2p.Peer, p2pKey *k1.PrivateKey,
	deadliner core.Deadliner, gaterFunc core.DutyGaterFunc, snifferFunc func(*pbv1.SniffedConsensusInstance),
) (core.ConsensusFactory, error) {
	defaultConsensus, err := qbft.NewConsensus(tcpNode, sender, peers, p2pKey, deadliner, gaterFunc, snifferFunc)
	if err != nil {
		return nil, err
	}

	return &consensusFactory{
		tcpNode:          tcpNode,
		sender:           sender,
		peers:            peers,
		p2pKey:           p2pKey,
		deadliner:        deadliner,
		gaterFunc:        gaterFunc,
		snifferFunc:      snifferFunc,
		defaultConsensus: defaultConsensus,
	}, nil
}

// DefaultConsensus returns the default consensus instance.
func (f *consensusFactory) DefaultConsensus() core.Consensus {
	return f.defaultConsensus
}

// ConsensusByProtocolID returns a consensus instance for the specified protocol ID.
func (f *consensusFactory) ConsensusByProtocolID(protocol protocol.ID) (core.Consensus, error) {
	if f.defaultConsensus.ProtocolID() == protocol {
		return f.defaultConsensus, nil
	}

	// TODO: support for more protocols, add map[protocol.ID]core.Consensus with a lock, etc.

	return nil, errors.New("unknown consensus protocol")
}
