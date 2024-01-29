// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package priority implements the priority protocol that resolves arbitrary cluster wide priorities.
//
// Protocol overview:
//   - Priorities are arbitrary protobufs (data).
//   - Priorities are grouped by a topic (also arbitrary protobuf data).
//   - Peers in the cluster participate in a priority protocol instances.
//   - The protocol consists of two steps: priority exchange followed by priority consensus.
//   - All peers propose their own set of priorities for an instance.
//   - These are exchanged with all other peers.
//   - All peers also respond with their priorities.
//   - The exchange step is complete when the priorities of all peers have been received or on timeout.
//   - Each peer calculates what they consider as the cluster wide priorities based on the priorities available to them at the point.
//   - Each peer then starts a consensus instance proposing this deterministic calculated result.
//   - Consensus is reached if quorum peers propose the same value.
package priority

import (
	"context"
	"sync"
	"testing"
	"time"

	ssz "github.com/ferranbt/fastssz"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/p2p"
)

const protocolID2 = "charon/priority/2.0.0"

// Protocols returns the supported protocols of this package in order of precedence.
func Protocols() []protocol.ID {
	return []protocol.ID{protocolID2}
}

// Topic groups priorities in an instance.
type Topic proto.Message

// Priority is one of many grouped by a Topic being prioritised in an Instance.
type Priority proto.Message

type Consensus interface {
	ProposePriority(context.Context, core.Duty, *pbv1.PriorityResult) error
	SubscribePriority(func(context.Context, core.Duty, *pbv1.PriorityResult) error)
}

// msgValidator abstracts validation of a received priority messages.
type msgValidator func(*pbv1.PriorityMsg) error

// subscriber abstracts the output subscriber callbacks of Prioritiser.
type subscriber func(context.Context, core.Duty, *pbv1.PriorityResult) error

// request contains a received peer request and a channel to provide response.
type request struct {
	Msg      *pbv1.PriorityMsg
	Response chan<- *pbv1.PriorityMsg
}

// NewForT exports newInternal for testing and returns a new prioritiser.
func NewForT(_ *testing.T, tcpNode host.Host, peers []peer.ID, minRequired int,
	sendFunc p2p.SendReceiveFunc, registerHandlerFunc p2p.RegisterHandlerFunc,
	consensus Consensus, msgValidator msgValidator, exchangeTimeout time.Duration,
	deadliner core.Deadliner,
) *Prioritiser {
	return newInternal(tcpNode, peers, minRequired, sendFunc, registerHandlerFunc,
		consensus, msgValidator, exchangeTimeout, deadliner)
}

// newInternal returns a new prioritiser, it is the constructor.
func newInternal(tcpNode host.Host, peers []peer.ID, minRequired int,
	sendFunc p2p.SendReceiveFunc, registerHandlerFunc p2p.RegisterHandlerFunc,
	consensus Consensus, msgValidator msgValidator,
	exchangeTimeout time.Duration, deadliner core.Deadliner,
) *Prioritiser {
	// Create log filters
	noSupportFilters := make(map[peer.ID]z.Field)
	for _, peerID := range peers {
		noSupportFilters[peerID] = log.Filter()
	}

	p := &Prioritiser{
		tcpNode:          tcpNode,
		sendFunc:         sendFunc,
		minRequired:      minRequired,
		peers:            peers,
		consensus:        consensus,
		msgValidator:     msgValidator,
		exchangeTimeout:  exchangeTimeout,
		deadliner:        deadliner,
		quit:             make(chan struct{}),
		noSupportFilters: noSupportFilters,
		skipAllFilter:    log.Filter(),
		reqBuffers:       make(map[core.Duty]chan request),
	}

	// Wire consensus output to Prioritiser subscribers.
	consensus.SubscribePriority(func(ctx context.Context, duty core.Duty, result *pbv1.PriorityResult) error {
		for _, sub := range p.subs {
			if err := sub(ctx, duty, result); err != nil {
				return err
			}
		}

		return nil
	})

	// Register prioritiser protocol handler.
	registerHandlerFunc("priority", tcpNode, protocolID2,
		func() proto.Message { return new(pbv1.PriorityMsg) },
		func(ctx context.Context, pID peer.ID, msg proto.Message) (proto.Message, bool, error) {
			prioMsg, ok := msg.(*pbv1.PriorityMsg)
			if !ok || prioMsg == nil {
				return nil, false, errors.New("invalid priority message")
			}

			resp, err := p.handleRequest(ctx, pID, prioMsg)
			if err != nil {
				return nil, false, errors.Wrap(err, "handle priority request",
					z.Any("duty", core.DutyFromProto(prioMsg.Duty)))
			}

			return resp, true, nil
		})

	return p
}

// Prioritiser resolves cluster wide priorities.
type Prioritiser struct {
	// Immutable state

	quit             chan struct{}
	deadliner        core.Deadliner
	minRequired      int
	exchangeTimeout  time.Duration
	tcpNode          host.Host
	sendFunc         p2p.SendReceiveFunc
	peers            []peer.ID
	consensus        Consensus
	msgValidator     msgValidator
	subs             []subscriber
	noSupportFilters map[peer.ID]z.Field
	skipAllFilter    z.Field

	// Mutable state

	reqMu      sync.Mutex
	reqBuffers map[core.Duty]chan request
}

// Start starts a goroutine that cleans state.
// This must only be called once.
func (p *Prioritiser) Start(ctx context.Context) {
	go func() {
		defer close(p.quit)
		for {
			select {
			case <-ctx.Done():
				return
			case duty := <-p.deadliner.C():
				p.deleteRecvBuffer(duty)
			}
		}
	}()
}

// Subscribe registers a prioritiser output subscriber function.
// This is not thread safe and MUST NOT be called after Run.
func (p *Prioritiser) Subscribe(fn subscriber) {
	p.subs = append(p.subs, fn)
}

// Prioritise starts a new prioritisation instance for the provided message or returns an error.
func (p *Prioritiser) Prioritise(ctx context.Context, msg *pbv1.PriorityMsg) error {
	duty := core.DutyFromProto(msg.Duty)
	ctx = log.WithCtx(ctx, z.Any("duty", duty))

	if !p.deadliner.Add(duty) {
		log.Warn(ctx, "Dropping priority protocol instance for expired duty", nil)
		return nil
	}

	return runInstance(ctx, duty, msg, p.getReqBuffer(duty), p.minRequired,
		p.exchangeTimeout, p.tcpNode, p.sendFunc, p.peers, p.consensus, p.msgValidator)
}

// handleRequest handles a priority message exchange initiated by a peer.
func (p *Prioritiser) handleRequest(ctx context.Context, pID peer.ID, msg *pbv1.PriorityMsg) (*pbv1.PriorityMsg, error) {
	if msg == nil {
		return nil, errors.New("nil priority message")
	}

	if pID.String() != msg.PeerId {
		return nil, errors.New("invalid priority message peer id", z.Str("expect", pID.String()), z.Str("actual", msg.PeerId))
	} else if err := p.msgValidator(msg); err != nil {
		return nil, errors.Wrap(err, "invalid priority message")
	}

	response := make(chan *pbv1.PriorityMsg, 1) // Ensure responding goroutine never blocks.
	req := request{
		Msg:      msg,
		Response: response,
	}

	duty := core.DutyFromProto(msg.Duty)

	if !p.deadliner.Add(duty) {
		return nil, errors.New("duty expired")
	}

	reqBuffer := p.getReqBuffer(duty)

	select {
	case reqBuffer <- req:
	case <-ctx.Done():
		return nil, errors.Wrap(ctx.Err(), "timeout enqueuing request")
	case <-p.quit:
		return nil, errors.New("prioritiser shutdown")
	}

	select {
	case resp := <-response:
		return resp, nil
	case <-ctx.Done():
		return nil, errors.Wrap(ctx.Err(), "timeout waiting for proposed priorities")
	case <-p.quit:
		return nil, errors.New("prioritiser shutdown")
	}
}

// getReqBuffer returns a request buffer for the duty instance.
func (p *Prioritiser) getReqBuffer(duty core.Duty) chan request {
	p.reqMu.Lock()
	defer p.reqMu.Unlock()

	ch, ok := p.reqBuffers[duty]
	if !ok {
		ch = make(chan request, 2*len(p.peers))
		p.reqBuffers[duty] = ch
	}

	return ch
}

// deleteRecvBuffer deletes the receive channel and recvDropped map entry for the duty.
func (p *Prioritiser) deleteRecvBuffer(duty core.Duty) {
	p.reqMu.Lock()
	defer p.reqMu.Unlock()

	delete(p.reqBuffers, duty)
}

// runInstance blocks until the context is closed. It exchanges messages with peers,
// responds to peer requests, and starts consensus.
func runInstance(ctx context.Context, duty core.Duty, own *pbv1.PriorityMsg,
	requests <-chan request, minRequired int, exchangeTimeout time.Duration,
	tcpNode host.Host, sendFunc p2p.SendReceiveFunc, peers []peer.ID,
	consensus Consensus, msgValidator msgValidator,
) error {
	log.Debug(ctx, "Priority protocol instance started")

	var (
		msgs        = []*pbv1.PriorityMsg{own}
		dedupPeers  = make(map[string]bool)
		responses   = make(chan *pbv1.PriorityMsg) // Responses from exchanging with peers.
		consStarted bool
	)

	// addMsg adds the first message of each peer to msgs.
	addMsg := func(msg *pbv1.PriorityMsg) {
		if dedupPeers[msg.PeerId] {
			return
		}
		dedupPeers[msg.PeerId] = true
		msgs = append(msgs, msg)
	}

	exTimeout := time.After(exchangeTimeout)

	exchange(ctx, tcpNode, peers, msgValidator, sendFunc, responses, own)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case req := <-requests:
			addMsg(req.Msg)
			req.Response <- own
		case msg := <-responses:
			addMsg(msg)
		case <-exTimeout:
			if consStarted {
				continue
			}

			log.Debug(ctx, "Priority protocol instance exchange timeout, starting consensus")
			consStarted = true
			err := startConsensus(ctx, duty, msgs, minRequired, consensus)
			if err != nil {
				return err
			}
		}

		if !consStarted && len(msgs) == len(peers) {
			log.Debug(ctx, "Priority protocol instance messages exchanged, starting consensus")
			consStarted = true
			err := startConsensus(ctx, duty, msgs, minRequired, consensus)
			if err != nil {
				return err
			}
		}
	}
}

// exchange initiates a priority message exchange with all peers.
func exchange(ctx context.Context, tcpNode host.Host, peers []peer.ID, msgValidator msgValidator,
	sendFunc p2p.SendReceiveFunc, responses chan<- *pbv1.PriorityMsg, own *pbv1.PriorityMsg,
) {
	for _, pID := range peers {
		if pID == tcpNode.ID() {
			continue // Do not send to self
		}

		go func(pID peer.ID) {
			response := new(pbv1.PriorityMsg)
			err := sendFunc(ctx, tcpNode, pID, own, response, protocolID2)
			if err != nil {
				// No need to log, since transport will do it.
				return
			}

			if pID.String() != response.PeerId {
				log.Warn(ctx, "Invalid priority message peer id", nil, z.Str("peer", p2p.PeerName(pID)))
				return
			}

			if err := msgValidator(response); err != nil {
				log.Warn(ctx, "Invalid priority message from peer", err, z.Str("peer", p2p.PeerName(pID)))
				return
			}

			select {
			case <-ctx.Done():
			case responses <- response:
			}
		}(pID)
	}
}

// startConsensus starts a consensus round.
func startConsensus(ctx context.Context, duty core.Duty, msgs []*pbv1.PriorityMsg, minRequired int, consensus Consensus) error {
	result, err := calculateResult(msgs, minRequired)
	if err != nil {
		return errors.Wrap(err, "calculate priority protocol result")
	}

	// Do consensus async, since it blocks and this instance still needs to process requests.
	go func() {
		err = consensus.ProposePriority(ctx, duty, result)
		if err != nil {
			log.Warn(ctx, "Priority protocol consensus", err) // Unexpected
		}
	}()

	return nil
}

// hashProto returns a deterministic ssz hash root of the proto message.
// It is the same logic as that used by the consensus package.
func hashProto(msg proto.Message) ([32]byte, error) {
	hh := ssz.DefaultHasherPool.Get()
	defer ssz.DefaultHasherPool.Put(hh)

	index := hh.Index()

	// Do deterministic marshalling.
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "marshal proto")
	}
	hh.PutBytes(b)

	hh.Merkleize(index)

	hash, err := hh.HashRoot()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash proto")
	}

	return hash, nil
}
