// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus

import (
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/consensus/protocols"
	"github.com/obolnetwork/charon/core/consensus/qbft"
	"github.com/obolnetwork/charon/p2p"
)

type DeadlinerFunc func(label string) core.Deadliner

type consensusFactory struct {
	tcpNode          host.Host
	sender           *p2p.Sender
	peers            []p2p.Peer
	p2pKey           *k1.PrivateKey
	deadlinerFunc    DeadlinerFunc
	gaterFunc        core.DutyGaterFunc
	debugger         Debugger
	defaultConsensus core.Consensus
	wrappedConsensus *consensusWrapper
}

// NewConsensusFactory creates a new consensus factory with the default consensus protocol.
func NewConsensusFactory(tcpNode host.Host, sender *p2p.Sender, peers []p2p.Peer, p2pKey *k1.PrivateKey,
	deadlinerFunc DeadlinerFunc, gaterFunc core.DutyGaterFunc, debugger Debugger,
) (core.ConsensusFactory, error) {
	qbftDeadliner := deadlinerFunc("consensus.qbft")
	defaultConsensus, err := qbft.NewConsensus(tcpNode, sender, peers, p2pKey, qbftDeadliner, gaterFunc, debugger.AddInstance)
	if err != nil {
		return nil, err
	}

	return &consensusFactory{
		tcpNode:          tcpNode,
		sender:           sender,
		peers:            peers,
		p2pKey:           p2pKey,
		deadlinerFunc:    deadlinerFunc,
		gaterFunc:        gaterFunc,
		debugger:         debugger,
		defaultConsensus: defaultConsensus,
		wrappedConsensus: newConsensusWrapper(defaultConsensus),
	}, nil
}

// DefaultConsensus returns the default consensus instance.
func (f *consensusFactory) DefaultConsensus() core.Consensus {
	return f.defaultConsensus
}

// CurrentConsensus returns the current consensus instance.
func (f *consensusFactory) CurrentConsensus() core.Consensus {
	return f.wrappedConsensus
}

// SetCurrentConsensusForProtocol sets the current consensus instance for the given protocol id.
func (f *consensusFactory) SetCurrentConsensusForProtocol(protocol protocol.ID) error {
	if f.wrappedConsensus.ProtocolID() == protocol {
		return nil
	}

	if protocol == protocols.QBFTv2ProtocolID {
		f.wrappedConsensus.SetImpl(f.defaultConsensus)

		return nil
	}

	return errors.New("unsupported protocol id")
}
