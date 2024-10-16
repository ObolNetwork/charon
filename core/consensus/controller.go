// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus

import (
	"context"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/consensus/qbft"
	"github.com/obolnetwork/charon/p2p"
)

type consensusController struct {
	tcpNode            host.Host
	sender             *p2p.Sender
	peers              []p2p.Peer
	p2pKey             *k1.PrivateKey
	consensusDeadliner core.Deadliner
	gaterFunc          core.DutyGaterFunc
	debugger           Debugger
	defaultConsensus   core.Consensus
	wrappedConsensus   *consensusWrapper
}

// NewConsensusController creates a new consensus controller with the default consensus protocol.
func NewConsensusController(tcpNode host.Host, sender *p2p.Sender, peers []p2p.Peer, p2pKey *k1.PrivateKey,
	consensusDeadliner core.Deadliner, gaterFunc core.DutyGaterFunc, debugger Debugger,
) (core.ConsensusController, error) {
	defaultConsensus, err := qbft.NewConsensus(tcpNode, sender, peers, p2pKey, consensusDeadliner, gaterFunc, debugger.AddInstance)
	if err != nil {
		return nil, err
	}

	return &consensusController{
		tcpNode:            tcpNode,
		sender:             sender,
		peers:              peers,
		p2pKey:             p2pKey,
		consensusDeadliner: consensusDeadliner,
		gaterFunc:          gaterFunc,
		debugger:           debugger,
		defaultConsensus:   defaultConsensus,
		wrappedConsensus:   newConsensusWrapper(defaultConsensus),
	}, nil
}

// Start starts the internal routines. The controller stops when the context is cancelled.
func (f *consensusController) Start(ctx context.Context) {
	// The default protocol remains registered all the time.
	f.defaultConsensus.RegisterHandler()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case duty := <-f.consensusDeadliner.C():
				f.defaultConsensus.HandleExpiredDuty(duty)
				if f.wrappedConsensus.ProtocolID() != f.defaultConsensus.ProtocolID() {
					f.wrappedConsensus.HandleExpiredDuty(duty)
				}
			}
		}
	}()
}

// DefaultConsensus returns the default consensus instance.
func (f *consensusController) DefaultConsensus() core.Consensus {
	return f.defaultConsensus
}

// CurrentConsensus returns the current consensus instance.
func (f *consensusController) CurrentConsensus() core.Consensus {
	return f.wrappedConsensus
}

// SetCurrentConsensusForProtocol sets the current consensus instance for the given protocol id.
func (f *consensusController) SetCurrentConsensusForProtocol(protocol protocol.ID) error {
	if f.wrappedConsensus.ProtocolID() == protocol {
		return nil
	}

	if protocol == f.defaultConsensus.ProtocolID() {
		f.wrappedConsensus.SetImpl(f.defaultConsensus)

		return nil
	}

	// TODO: Call RegisterHandler()/UnregisterHandler() when switching.

	return errors.New("unsupported protocol id")
}
