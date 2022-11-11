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
	"testing"
	"time"

	ssz "github.com/ferranbt/fastssz"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/p2p"
)

const (
	ProtocolID  = "charon/priority/1.0.0"
	deleteAfter = time.Minute
)

// Instance identifies an instance of the priority protocol.
type Instance proto.Message

// Topic groups priorities in an instance.
type Topic proto.Message

// Priority is one of many grouped by a Topic being prioritised in an Instance.
type Priority proto.Message

// instanceData contains an Instance and its data.
type instanceData struct {
	OwnID       string
	Instance    Instance
	Key         [32]byte                     // Hash of instance
	Pending     []chan<- *pbv1.PriorityMsg   // Pending exchange requests from peers
	Msgs        map[string]*pbv1.PriorityMsg // Received messages by peers (including own)
	Timeout     time.Time                    // Timeout starts consensus even if all messages not received
	ConsStarted bool                         // Whether consensus was started
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

// request contains a received peer request and a channel to provide response.
type request struct {
	Msg      *pbv1.PriorityMsg
	Response chan<- *pbv1.PriorityMsg
}

// NewForT exports newInternal for testing and returns a new prioritiser.
func NewForT(_ *testing.T, tcpNode host.Host, peers []peer.ID, minRequired int, sendFunc p2p.SendReceiveFunc, registerHandlerFunc p2p.RegisterHandlerFunc,
	consensus Consensus, msgValidator msgValidator,
	consensusTimeout time.Duration, tickerProvider tickerProvider,
) *Prioritiser {
	return newInternal(tcpNode, peers, minRequired, sendFunc, registerHandlerFunc, consensus, msgValidator, consensusTimeout, tickerProvider)
}

// newInternal returns a new prioritiser, it is the constructor.
func newInternal(tcpNode host.Host, peers []peer.ID, minRequired int, sendFunc p2p.SendReceiveFunc, registerHandlerFunc p2p.RegisterHandlerFunc,
	consensus Consensus, msgValidator msgValidator,
	consensusTimeout time.Duration, tickerProvider tickerProvider,
) *Prioritiser {
	// Create log filters
	noSupportFilters := make(map[peer.ID]z.Field)
	for _, peerID := range peers {
		noSupportFilters[peerID] = log.Filter()
	}

	n := &Prioritiser{
		tcpNode:          tcpNode,
		sendFunc:         sendFunc,
		minRequired:      minRequired,
		peers:            peers,
		consensus:        consensus,
		msgValidator:     msgValidator,
		consensusTimeout: consensusTimeout,
		tickerProvider:   tickerProvider,
		own:              make(chan *pbv1.PriorityMsg),
		responses:        make(chan *pbv1.PriorityMsg),
		requests:         make(chan request),
		quit:             make(chan struct{}),
		noSupportFilters: noSupportFilters,
		skipAllFilter:    log.Filter(),
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
	registerHandlerFunc("priority", tcpNode, ProtocolID,
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
	// All state immutable wrt Run.

	quit             chan struct{}
	own              chan *pbv1.PriorityMsg // Own proposed messages to exchange
	requests         chan request           // Other peers requesting to exchange messages.
	responses        chan *pbv1.PriorityMsg // Responses from exchanging with peers.
	minRequired      int
	consensusTimeout time.Duration
	tcpNode          host.Host
	sendFunc         p2p.SendReceiveFunc
	peers            []peer.ID
	consensus        Consensus
	msgValidator     msgValidator
	tickerProvider   tickerProvider
	subs             []subscriber
	noSupportFilters map[peer.ID]z.Field
	skipAllFilter    z.Field
}

// Subscribe registers a prioritiser output subscriber function.
// This is not thread safe and MUST NOT be called after Run.
func (p *Prioritiser) Subscribe(fn subscriber) {
	p.subs = append(p.subs, fn)
}

// Prioritise starts a new prioritisation instance for the provided message or returns an error.
func (p *Prioritiser) Prioritise(ctx context.Context, msg *pbv1.PriorityMsg) error {
	select {
	case p.own <- msg:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-p.quit:
		return errors.New("prioritiser shutdown")
	}
}

// Run runs the prioritiser until the context is cancelled.
// Note this will panic if called multiple times.
func (p *Prioritiser) Run(ctx context.Context) error {
	defer close(p.quit)
	ctx = log.WithTopic(ctx, "priority")

	ticker, stopTicker := p.tickerProvider()
	defer stopTicker()

	// Mutable state
	instances := make(map[[32]byte]instanceData)

	// startConsensus starts consensus and marks the instance as such.
	startConsensus := func(data instanceData) {
		var msgs []*pbv1.PriorityMsg
		for _, msg := range data.Msgs {
			msgs = append(msgs, msg)
		}
		result, err := calculateResult(msgs, p.minRequired)
		if err != nil {
			log.Error(ctx, "Calculate priority consensus", err) // Unexpected
			return
		}

		go func() {
			err = p.consensus.ProposePriority(ctx, data.Instance, result)
			if err != nil {
				log.Warn(ctx, "Propose priority consensus", err) // Unexpected
				return
			}
		}()

		data.ConsStarted = true
		instances[data.Key] = data
	}

	// processInstance calls the callback with new or existing instance data and
	// stores the result after processing any pending requests. It also starts consensus
	// if all messages were received.
	processInstance := func(instance *anypb.Any, callback func(instanceData) (instanceData, error)) {
		// TODO(corver): Instance needs a duty/slot so we can filter out unexpected instances.
		instancePB, err := instance.UnmarshalNew()
		if err != nil {
			log.Error(ctx, "Priority unmarshal any", err)
			return
		}
		key, err := hashProto(instancePB)
		if err != nil {
			log.Error(ctx, "Priority hash proto", err)
			return
		}

		data, ok := instances[key]
		if !ok {
			data = instanceData{
				OwnID:    p.tcpNode.ID().String(),
				Instance: instancePB,
				Key:      key,
				Msgs:     make(map[string]*pbv1.PriorityMsg),
				Timeout:  time.Now().Add(p.consensusTimeout),
			}
		}

		data, err = callback(data)
		if err != nil {
			log.Error(ctx, "Priority instance error", err)
			return
		}

		data = processPending(data)
		instances[key] = data

		if !data.ConsStarted && len(data.Msgs) == len(p.peers) {
			// All messages received before timeout
			log.Debug(ctx, "Priority instance received all messages, starting consensus")
			startConsensus(data)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg := <-p.own:
			log.Debug(ctx, "Priority protocol triggered")
			processInstance(msg.Instance, func(data instanceData) (instanceData, error) {
				data.Msgs[msg.PeerId] = msg
				return data, nil
			})
			p.exchangeOnce(ctx, msg)
		case req := <-p.requests:
			processInstance(req.Msg.Instance, func(data instanceData) (instanceData, error) {
				data.Msgs[req.Msg.PeerId] = req.Msg
				data.Pending = append(data.Pending, req.Response)

				return data, nil
			})
		case msg := <-p.responses:
			processInstance(msg.Instance, func(data instanceData) (instanceData, error) {
				data.Msgs[msg.PeerId] = msg
				return data, nil
			})
		case now := <-ticker:
			for _, data := range instances {
				if now.Before(data.Timeout) {
					continue // Not timed out yet.
				}
				if !data.ConsStarted { // Timed out and consensus not started yet.
					log.Debug(ctx, "Priority instance timeout, starting consensus")
					startConsensus(data)

					continue
				}
				if now.Before(data.Timeout.Add(deleteAfter)) {
					continue // Not deletable yet
				}

				delete(instances, data.Key)
			}
		}
	}
}

// handleRequest handles a priority message exchange initiated by a peer.
func (p *Prioritiser) handleRequest(ctx context.Context, pID peer.ID, msg *pbv1.PriorityMsg) (*pbv1.PriorityMsg, error) {
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

	select {
	case p.requests <- req:
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

// exchangeOnce initiates a priority message exchange with all peers.
func (p *Prioritiser) exchangeOnce(ctx context.Context, msg *pbv1.PriorityMsg) {
	if !p.quorumSupported(ctx) {
		log.Warn(ctx, "Skipping non-critical priority protocol not supported by quorum peers", nil, p.skipAllFilter)
		return
	}

	for _, pID := range p.peers {
		if pID == p.tcpNode.ID() {
			continue // Do not send to self
		}

		go func(pID peer.ID) {
			response := new(pbv1.PriorityMsg)
			err := p.sendFunc(ctx, p.tcpNode, pID, msg, response, ProtocolID)
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
			case p.responses <- response:
			}
		}(pID)
	}
}

// quorumSupported returns true if at least quorum peers support the priority protocol.
func (p *Prioritiser) quorumSupported(ctx context.Context) bool {
	var count int
	for _, peerID := range p.peers {
		// Check if peer supports this protocol.
		if protocols, err := p.tcpNode.Peerstore().GetProtocols(peerID); err != nil || len(protocols) == 0 {
			// Ignore peer until some protocols detected
			continue
		} else if !supported(protocols) {
			log.Warn(ctx, "Non-critical priority protocol not supported by peer", nil,
				z.Str("peer", p2p.PeerName(peerID)),
				p.noSupportFilters[peerID],
			)

			continue
		}
		count++
	}

	return (count + 1) >= p.minRequired // Include ourselves in count
}

// supported returns true if the priority ProtocolID is included in the list of protocols.
func supported(protocols []string) bool {
	for _, p := range protocols {
		if p == ProtocolID {
			return true
		}
	}

	return false
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

// processPending sends own proposed msg to any awaiting/pending peers removing them from the returned instance.
func processPending(data instanceData) instanceData {
	// Get own message
	own, ok := data.Msgs[data.OwnID]
	if !ok {
		// Own message not received yet
		return data
	}

	// Send own to any awaiting peers
	for _, ch := range data.Pending {
		ch <- own
	}

	// Clear pending
	data.Pending = nil

	return data
}
