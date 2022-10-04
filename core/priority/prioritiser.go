// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

// Package priority implements the priority protocol that resolves arbitrary cluster wide priorities.
package priority

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/p2p"
)

const protocolID = "charon/priority/1.0.0"

type Consensus interface {
	ProposePriority(ctx context.Context, slot int64, result *pbv1.PriorityResult) error
	SubscribePriority(func(ctx context.Context, slot int64, result *pbv1.PriorityResult) error)
}

// msgProvider abstracts creation of a new signed priority messages.
type msgProvider func(slot int64) (*pbv1.PriorityMsg, error)

// msgValidator abstracts validation of a received priority messages.
type msgValidator func(*pbv1.PriorityMsg) error

// tickerProvider abstracts the consensus timeout ticker (for testing purposes only).
type tickerProvider func() (<-chan time.Time, func())

// subscriber abstracts the output subscriber callbacks of Prioritiser.
type subscriber func(ctx context.Context, slot int64, topic string, priorities []*pbv1.PriorityScoredResult) error

func NewForT(tcpNode host.Host, peers []peer.ID, minRequired int, sendFunc p2p.SendReceiveFunc, registerHandlerFunc p2p.RegisterHandlerFunc,
	consensus Consensus, msgProvider msgProvider, msgValidator msgValidator,
	consensusTimeout time.Duration, tickerProvider tickerProvider,
) *Prioritiser {
	n := &Prioritiser{
		tcpNode:          tcpNode,
		sendFunc:         sendFunc,
		minRequired:      minRequired,
		peers:            peers,
		consensus:        consensus,
		msgProvider:      msgProvider,
		msgValidator:     msgValidator,
		consensusTimeout: consensusTimeout,
		tickerProvider:   tickerProvider,
		subs:             make(map[string][]subscriber),
		trigger:          make(chan int64, 1), // Buffer a single trigger
		received:         make(chan *pbv1.PriorityMsg),
		quit:             make(chan struct{}),
	}

	// Wire consensus output to Prioritiser subscribers.
	consensus.SubscribePriority(func(ctx context.Context, slot int64, result *pbv1.PriorityResult) error {
		for _, topic := range result.Topics {
			for _, sub := range n.subs[topic.Topic] {
				if err := sub(ctx, slot, topic.Topic, topic.Priorities); err != nil {
					return err
				}
			}
		}

		return nil
	})

	// Register prioritiser protocol handler.
	registerHandlerFunc("priority", tcpNode, protocolID,
		func() proto.Message { return new(pbv1.PriorityMsg) },
		func(ctx context.Context, pID peer.ID, msg proto.Message) (proto.Message, bool, error) {
			prioMsg, ok := msg.(*pbv1.PriorityMsg)
			if !ok {
				return nil, false, errors.New("invalid priority message")
			}

			resp, err := n.handleRequest(ctx, pID, prioMsg)

			return resp, true, err
		})

	return n
}

// Prioritiser resolves cluster wide priorities.
type Prioritiser struct {
	quit             chan struct{}
	trigger          chan int64
	received         chan *pbv1.PriorityMsg
	minRequired      int
	consensusTimeout time.Duration
	tcpNode          host.Host
	sendFunc         p2p.SendReceiveFunc
	peers            []peer.ID
	consensus        Consensus
	msgProvider      msgProvider
	msgValidator     msgValidator
	tickerProvider   tickerProvider
	subs             map[string][]subscriber
}

// Subscribe registers a prioritiser output subscriber function.
// This is not thread safe and MUST NOT be called after Run.
func (p *Prioritiser) Subscribe(topic string, fn subscriber) {
	p.subs[topic] = append(p.subs[topic], fn)
}

// Prioritise starts a new prioritisation round for the provided slot.
func (p *Prioritiser) Prioritise(slot int64) {
	select {
	case p.trigger <- slot:
	case <-p.quit:
	}
}

// Run runs the prioritiser until the context is cancelled.
// Note this will panic if called multiple times.
//
//nolint:gocognit // Not that bad I feel.
func (p *Prioritiser) Run(ctx context.Context) error {
	defer close(p.quit)
	ctx = log.WithTopic(ctx, "priority")

	ticker, stopTicker := p.tickerProvider()
	defer stopTicker()

	var (
		msgs          = make(map[int64]map[peer.ID]*pbv1.PriorityMsg)
		timeouts      = make(map[int64]time.Time)
		completedSlot int64
	)

	startConsensus := func(slot int64) {
		var slotMsgs []*pbv1.PriorityMsg
		for _, msg := range msgs[slot] {
			slotMsgs = append(slotMsgs, msg)
		}
		result, err := calculateResult(slotMsgs, p.minRequired)
		if err != nil {
			log.Error(ctx, "Calculate priority consensus", err) // Unexpected
			return
		}

		err = p.consensus.ProposePriority(ctx, slot, result)
		if err != nil {
			log.Warn(ctx, "Propose priority consensus", err) // Unexpected
			return
		}

		completedSlot = slot
		delete(msgs, slot)
		delete(timeouts, slot)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case slot := <-p.trigger:
			if slot <= completedSlot {
				continue // Ignore triggers for completed slots.
			}

			err := p.prioritiseOnce(ctx, slot)
			if err != nil {
				log.Warn(ctx, "Priority error", err)
			}

		case msg := <-p.received:
			if msg.Slot <= completedSlot {
				continue // Ignore messages for completed slots.
			}

			slotMsgs, ok := msgs[msg.Slot]
			if !ok {
				slotMsgs = make(map[peer.ID]*pbv1.PriorityMsg)
				timeouts[msg.Slot] = time.Now().Add(p.consensusTimeout)
			}
			slotMsgs[peer.ID(msg.PeerId)] = msg
			msgs[msg.Slot] = slotMsgs

			if len(slotMsgs) == len(p.peers) {
				// All messages received before timeout
				startConsensus(msg.Slot)
			}
		case now := <-ticker:
			for slot, timeout := range timeouts {
				if now.Before(timeout) {
					continue
				}

				startConsensus(slot) // Note that iterating and deleting from a map from a single goroutine is fine.
			}
		}
	}
}

// handleRequest handles a priority message exchange initiated by a peer.
func (p *Prioritiser) handleRequest(ctx context.Context, pID peer.ID, msg *pbv1.PriorityMsg) (*pbv1.PriorityMsg, error) {
	if pID.String() != msg.PeerId {
		return nil, errors.New("invalid priority message peer id")
	} else if err := p.msgValidator(msg); err != nil {
		return nil, errors.Wrap(err, "invalid priority message")
	}

	select {
	case p.received <- msg:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.quit:
		return nil, errors.New("prioritiser shutdown")
	}

	resp, err := p.msgProvider(msg.Slot)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// prioritiseOnce initiates a priority message exchange with all peers.
func (p *Prioritiser) prioritiseOnce(ctx context.Context, slot int64) error {
	msg, err := p.msgProvider(slot)
	if err != nil {
		return err
	}

	// Send our own message first to start consensus timeout.
	go func() { // Async since unbuffered
		p.received <- msg
	}()

	for _, pID := range p.peers {
		if pID == p.tcpNode.ID() {
			continue // Do not send to self
		}

		go func(pID peer.ID) {
			response := new(pbv1.PriorityMsg)
			err := p.sendFunc(ctx, p.tcpNode, pID, msg, response, protocolID)
			if err != nil {
				// No need to log, since transport will do it.
				return
			}

			if pID.String() != response.PeerId {
				log.Warn(ctx, "Invalid priority message peer id", nil)
				return
			}

			if err := p.msgValidator(response); err != nil {
				log.Warn(ctx, "Invalid priority message from peer", err, z.Str("peer", p2p.PeerName(peer.ID(msg.PeerId))))
				return
			}

			p.received <- response
		}(pID)
	}

	return nil
}
