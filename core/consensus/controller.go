// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus

import (
	"context"
	"sync"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/consensus/qbft"
	"github.com/obolnetwork/charon/p2p"
)

type DeadlinerFactory func(name string) core.Deadliner

type consensusController struct {
	tcpNode          host.Host
	sender           *p2p.Sender
	peers            []p2p.Peer
	p2pKey           *k1.PrivateKey
	gaterFunc        core.DutyGaterFunc
	deadlineFunc     core.DeadlineFunc
	debugger         Debugger
	defaultConsensus core.Consensus
	wrappedConsensus *consensusWrapper

	mutable struct {
		sync.Mutex
		cancelWrappedCtx context.CancelFunc
	}
}

// NewConsensusController creates a new consensus controller with the default consensus protocol.
func NewConsensusController(ctx context.Context, tcpNode host.Host, sender *p2p.Sender,
	peers []p2p.Peer, p2pKey *k1.PrivateKey, deadlineFunc core.DeadlineFunc,
	gaterFunc core.DutyGaterFunc, debugger Debugger,
) (core.ConsensusController, error) {
	qbftDeadliner := core.NewDeadliner(ctx, "consensus.qbft", deadlineFunc)
	defaultConsensus, err := qbft.NewConsensus(tcpNode, sender, peers, p2pKey, qbftDeadliner, gaterFunc, debugger.AddInstance)
	if err != nil {
		return nil, err
	}

	return &consensusController{
		tcpNode:          tcpNode,
		sender:           sender,
		peers:            peers,
		p2pKey:           p2pKey,
		gaterFunc:        gaterFunc,
		deadlineFunc:     deadlineFunc,
		debugger:         debugger,
		defaultConsensus: defaultConsensus,
		wrappedConsensus: newConsensusWrapper(defaultConsensus),
	}, nil
}

func (f *consensusController) Start(ctx context.Context) {
	f.defaultConsensus.Start(ctx)

	go func() {
		<-ctx.Done()

		f.mutable.Lock()
		defer f.mutable.Unlock()

		if f.mutable.cancelWrappedCtx != nil {
			f.mutable.cancelWrappedCtx()
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
func (f *consensusController) SetCurrentConsensusForProtocol(_ context.Context, protocol protocol.ID) error {
	if f.wrappedConsensus.ProtocolID() == protocol {
		return nil
	}

	if protocol == f.defaultConsensus.ProtocolID() {
		f.wrappedConsensus.SetImpl(f.defaultConsensus)

		return nil
	}

	// TODO: When introducing new consensus protocols, add them here as follow:
	/*
		cctx, cancel := context.WithCancel(ctx)

		f.mutable.Lock()
		defer f.mutable.Unlock()

		if f.mutable.cancelWrappedCtx != nil {
			// Stopping the previous consensus instance if not the default one.
			f.mutable.cancelWrappedCtx()
		}

		xyzDeadliner := core.NewDeadliner(cctx, "consensus.xyz", f.deadlineFunc)
		xyzConsensus := xyz.NewConsensus(...)

		f.mutable.cancelWrappedCtx = cancel
		f.wrappedConsensus.SetImpl(xyzConsensus)

		xyzConsensus.Start(cctx)
	*/

	return errors.New("unsupported protocol id")
}
