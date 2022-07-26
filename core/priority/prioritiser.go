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
	"testing"
	"time"

	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/p2p"
)

const protocolID = "charon/priority/1.0.0"

// Transport abstracts sending and receiving libp2p protobuf message.
type Transport interface {
	// SendReceive sends the request to the peer and return a single response.
	SendReceive(
		ctx context.Context,
		peer peer.ID,
		req, resp proto.Message,
		protocols ...protocol.ID) bool

	// ReceiveSend registers a callback function that will be invoked when peers
	// send requests, replying with this peer's response.
	ReceiveSend(
		zeroReq func() proto.Message,
		callback func(ctx context.Context, peer peer.ID, request proto.Message) (proto.Message, error),
		protocols ...protocol.ID)
}

type Consensus interface {
	Propose(ctx context.Context, slot int64, result *pbv1.PriorityResult) error
	Subscribe(func(ctx context.Context, slot int64, result *pbv1.PriorityResult) error)
}

// msgProvider abstracts creation of a new signed priority messages.
type msgProvider func(slot int64) (*pbv1.PriorityMsg, error)

// msgValidator abstracts validation of a received priority messages.
type msgValidator func(*pbv1.PriorityMsg) error

// tickerProvider abstracts the consensus timeout ticker (for testing purposes only).
type tickerProvider func() (<-chan time.Time, func())

// subscriber abstracts the output subscriber callbacks of Prioritiser.
type subscriber func(ctx context.Context, slot int64, topic string, priorities []string) error

// NewForT returns a new prioritiser for testing.
func NewForT(_ *testing.T, transport Transport,
	consensus Consensus, msgProvider msgProvider, msgValidator msgValidator,
	consensusTimeout time.Duration, tickerProvider tickerProvider,
) *Prioritiser {
	n := &Prioritiser{
		transport:        transport,
		consensus:        consensus,
		msgProvider:      msgProvider,
		msgValidator:     msgValidator,
		consensusTimeout: consensusTimeout,
		tickerProvider:   tickerProvider,
		subs:             make(map[string][]subscriber),
		trigger:          make(chan int64, 1), // Buffer a single trigger
	}

	// Wire consensus output to Prioritiser subscribers.
	consensus.Subscribe(func(ctx context.Context, slot int64, result *pbv1.PriorityResult) error {
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
	transport.ReceiveSend(
		func() proto.Message { return new(pbv1.PriorityMsg) },
		func(ctx context.Context, pID peer.ID, msg proto.Message) (proto.Message, error) {
			prioMsg, ok := msg.(*pbv1.PriorityMsg)
			if !ok {
				return nil, errors.New("invalid priority message")
			}

			return n.handleRequest(ctx, pID, prioMsg)
		},
		protocolID)

	return n
}

// Prioritiser resolves cluster wide priorities.
type Prioritiser struct {
	quit             chan struct{}
	trigger          chan int64
	received         chan *pbv1.PriorityMsg
	minRequired      int
	consensusTimeout time.Duration
	transport        Transport
	peers            []peer.ID
	consensus        Consensus
	msgProvider      msgProvider
	msgValidator     msgValidator
	tickerProvider   tickerProvider
	subs             map[string][]subscriber
}

// Subscribe registers a prioritiser output subscriber function.
// This is not thread safe and MUST NOT be called after Run.
func (n *Prioritiser) Subscribe(topic string, fn subscriber) {
	n.subs[topic] = append(n.subs[topic], fn)
}

// Prioritise starts a new prioritisation round for the provided slot.
func (n *Prioritiser) Prioritise(slot int64) {
	select {
	case n.trigger <- slot:
	case <-n.quit:
	}
}

// Run runs the prioritiser until the context is cancelled.
// Note this will panic if called multiple times.
//nolint:gocognit // Not that bad I feel.
func (n *Prioritiser) Run(ctx context.Context) error {
	defer close(n.quit)

	ticker, stopTicker := n.tickerProvider()
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
		result, err := calculateResult(slotMsgs, n.minRequired)
		if err != nil {
			log.Error(ctx, "Validate priority consensus", err) // Unexpected
			return
		}

		err = n.consensus.Propose(ctx, slot, result)
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
		case slot := <-n.trigger:
			if slot <= completedSlot {
				continue // Ignore triggers for completed slots.
			}

			err := n.prioritiseOnce(ctx, slot)
			if err != nil {
				log.Warn(ctx, "Priority error", err)
			}

		case msg := <-n.received:
			if msg.Slot <= completedSlot {
				continue // Ignore messages for completed slots.
			}

			slotMsgs, ok := msgs[msg.Slot]
			if !ok {
				slotMsgs = make(map[peer.ID]*pbv1.PriorityMsg)
				timeouts[msg.Slot] = time.Now().Add(n.consensusTimeout)
			}
			slotMsgs[peer.ID(msg.PeerId)] = msg
			msgs[msg.Slot] = slotMsgs

			if len(slotMsgs) == len(n.peers) {
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
func (n *Prioritiser) handleRequest(ctx context.Context, pID peer.ID, msg *pbv1.PriorityMsg) (*pbv1.PriorityMsg, error) {
	if string(pID) != msg.PeerId {
		return nil, errors.New("invalid priority message peer id")
	} else if err := n.msgValidator(msg); err != nil {
		return nil, errors.Wrap(err, "invalid priority message")
	}

	select {
	case n.received <- msg:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-n.quit:
		return nil, errors.New("prioritiser shutdown")
	}

	return n.msgProvider(msg.Slot)
}

// prioritiseOnce initiates a priority message exchange with all peers.
func (n *Prioritiser) prioritiseOnce(ctx context.Context, slot int64) error {
	msg, err := n.msgProvider(slot)
	if err != nil {
		return err
	}

	// Send our own message first to start consensus timeout.
	n.received <- msg

	for _, pID := range n.peers {
		go func(pID peer.ID) {
			response := new(pbv1.PriorityMsg)
			ok := n.transport.SendReceive(ctx, pID, msg, response, protocolID)
			if !ok {
				// No need to log, since transport will do it.
				return
			}

			if string(pID) != msg.PeerId {
				log.Warn(ctx, "Invalid priority message peer id", nil)
				return
			}

			if err := n.msgValidator(msg); err != nil {
				log.Warn(ctx, "Invalid priority message from peer", err, z.Str("peer", p2p.PeerName(peer.ID(msg.PeerId))))
				return
			}

			n.received <- msg
		}(pID)
	}

	return nil
}
