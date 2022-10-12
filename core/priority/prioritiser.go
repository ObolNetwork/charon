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

	ssz "github.com/ferranbt/fastssz"
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

// Instance identifies an instance of the priority protocol.
type Instance proto.Message

// Topic groups priorities in an instance.
type Topic proto.Message

// Priority is one of many grouped by a Topic being prioritised in an Instance.
type Priority proto.Message

// instanceKey is the hash of an Instance proto.Message and is used to index instanceData. See hashProto.
type instanceKey [32]byte

// instanceData contains an Instance and its data.
type instanceData struct {
	Instance Instance
	Msgs     map[string]received // map[peerID]msg
	Timeout  time.Time
}

type Consensus interface {
	ProposePriority(context.Context, Instance, *pbv1.PriorityResult) error
	SubscribePriority(func(context.Context, Instance, *pbv1.PriorityResult) error)
}

// msgValidator abstracts validation of a received priority messages.
type msgValidator func(*pbv1.PriorityMsg) error

// tickerProvider abstracts the consensus timeout ticker (for testing purposes only).
type tickerProvider func() (<-chan time.Time, func())

// subscriber abstracts the output subscriber callbacks of Prioritiser.
type subscriber func(context.Context, Instance, *pbv1.PriorityResult) error

// received contains a received peer message and a channel to provide response.
type received struct {
	Own      bool
	Msg      *pbv1.PriorityMsg
	Response chan<- *pbv1.PriorityMsg
}

func NewForT(tcpNode host.Host, peers []peer.ID, minRequired int, sendFunc p2p.SendReceiveFunc, registerHandlerFunc p2p.RegisterHandlerFunc,
	consensus Consensus, msgValidator msgValidator,
	consensusTimeout time.Duration, tickerProvider tickerProvider,
) *Prioritiser {
	n := &Prioritiser{
		tcpNode:          tcpNode,
		sendFunc:         sendFunc,
		minRequired:      minRequired,
		peers:            peers,
		consensus:        consensus,
		msgValidator:     msgValidator,
		consensusTimeout: consensusTimeout,
		tickerProvider:   tickerProvider,
		proposals:        make(chan *pbv1.PriorityMsg),
		receives:         make(chan received),
		quit:             make(chan struct{}),
	}

	// Wire consensus output to Prioritiser subscribers.
	consensus.SubscribePriority(func(ctx context.Context, instance Instance, result *pbv1.PriorityResult) error {
		for _, sub := range n.subs {
			if err := sub(ctx, instance, result); err != nil {
				return err
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
	proposals        chan *pbv1.PriorityMsg
	receives         chan received
	minRequired      int
	consensusTimeout time.Duration
	tcpNode          host.Host
	sendFunc         p2p.SendReceiveFunc
	peers            []peer.ID
	consensus        Consensus
	msgValidator     msgValidator
	tickerProvider   tickerProvider
	subs             []subscriber
}

// Subscribe registers a prioritiser output subscriber function.
// This is not thread safe and MUST NOT be called after Run.
func (p *Prioritiser) Subscribe(fn subscriber) {
	p.subs = append(p.subs, fn)
}

// Prioritise starts a new prioritisation instance for the provided message or returns an error.
func (p *Prioritiser) Prioritise(ctx context.Context, msg *pbv1.PriorityMsg) error {
	select {
	case p.proposals <- msg:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-p.quit:
		return errors.New("prioritiser shutdown")
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

	instances := make(map[instanceKey]instanceData)

	startConsensus := func(key instanceKey) {
		data := instances[key]

		var msgs []*pbv1.PriorityMsg
		for _, msg := range data.Msgs {
			msgs = append(msgs, msg.Msg)
		}
		result, err := calculateResult(msgs, p.minRequired)
		if err != nil {
			log.Error(ctx, "Calculate priority consensus", err) // Unexpected
			return
		}

		err = p.consensus.ProposePriority(ctx, data.Instance, result)
		if err != nil {
			log.Warn(ctx, "Propose priority consensus", err) // Unexpected
			return
		}

		delete(instances, key)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg := <-p.proposals:
			p.prioritiseOnce(ctx, msg)

		case recv := <-p.receives:
			instance, err := recv.Msg.Instance.UnmarshalNew()
			if err != nil {
				log.Error(ctx, "Priority instance from any proto", err)
				continue
			}
			key, err := hashProto(instance)
			if err != nil {
				log.Error(ctx, "Priority instance key", err)
				continue
			}

			data, ok := instances[key]
			if !ok {
				data = instanceData{
					Instance: instance,
					Msgs:     make(map[string]received),
					Timeout:  time.Now().Add(p.consensusTimeout),
				}
			}
			sendResponse(data.Msgs, recv)
			data.Msgs[recv.Msg.PeerId] = recv
			instances[key] = data

			if len(data.Msgs) == len(p.peers) {
				// All messages received before timeout
				startConsensus(key)
			}
		case now := <-ticker:
			for key, data := range instances {
				if now.Before(data.Timeout) {
					continue
				}

				startConsensus(key) // Note that iterating and deleting from a map from a single goroutine is fine.
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

	response := make(chan *pbv1.PriorityMsg, 1) // Ensure responding goroutine never blocks.
	recv := received{
		Msg:      msg,
		Response: response,
	}

	select {
	case p.receives <- recv:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.quit:
		return nil, errors.New("prioritiser shutdown")
	}

	select {
	case resp := <-response:
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.quit:
		return nil, errors.New("prioritiser shutdown")
	}
}

// prioritiseOnce initiates a priority message exchange with all peers.
func (p *Prioritiser) prioritiseOnce(ctx context.Context, msg *pbv1.PriorityMsg) {
	// Send our own message first to start consensus timeout.
	go func() { // Async since unbuffered
		select {
		case <-ctx.Done():
		case p.receives <- received{
			Own: true,
			Msg: msg,
		}:
		}
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

			select {
			case <-ctx.Done():
			case p.receives <- received{Msg: response}:
			}
		}(pID)
	}
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

// sendResponse sends own response to any awaiting peers.
func sendResponse(msgs map[string]received, recv received) {
	if recv.Own { // Send our message to all waiting peers.
		for _, other := range msgs {
			if other.Response == nil {
				continue
			}
			other.Response <- recv.Msg
		}

		return
	}

	if recv.Response == nil {
		// This peer doesn't need a response
		return
	}

	// Send own response to this peer.
	for _, other := range msgs {
		if !other.Own {
			continue
		}
		recv.Response <- other.Msg
	}
}
