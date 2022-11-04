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

package priority

import (
	"context"
	"crypto/ecdsa"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/p2p"
)

// TopicProposal defines the proposed priorities of a single prioritise topic.
type TopicProposal struct {
	Topic      string
	Priorities []string
}

// TopicResult defines the resulting cluster-agreed upon priorities of a single prioritise topic.
type TopicResult struct {
	Topic      string
	Priorities []ScoredPriority
}

// ScoredPriority defines a resulting cluster-agreed priority including its score.
type ScoredPriority struct {
	Priority string
	Score    int
}

// coreConsensus is an interface for the core/consensus.Component.
type coreConsensus interface {
	ProposePriority(context.Context, core.Duty, *pbv1.PriorityResult) error
	SubscribePriority(func(context.Context, core.Duty, *pbv1.PriorityResult) error)
}

// NewComponent returns a new priority component.
func NewComponent(tcpNode host.Host, peers []peer.ID, minRequired int, sendFunc p2p.SendReceiveFunc,
	registerHandlerFunc p2p.RegisterHandlerFunc, consensus coreConsensus,
	slotDuration time.Duration, privkey *ecdsa.PrivateKey,
) (*Component, error) {
	verifier, err := newMsgVerifier(peers)
	if err != nil {
		return nil, err
	}

	tickerProvider := func() (<-chan time.Time, func()) {
		ticker := time.NewTicker(slotDuration / 10)
		return ticker.C, ticker.Stop
	}

	prioritiser := newInternal(tcpNode, peers, minRequired, sendFunc, registerHandlerFunc,
		consensusWrapper{consensus}, verifier, slotDuration, tickerProvider)

	return &Component{
		prioritiser: prioritiser,
		privkey:     privkey,
	}, nil
}

// Component wraps a prioritise protocol instance providing a friendly API (hiding the underlying protobuf types) and does signing.
type Component struct {
	peerID      peer.ID
	privkey     *ecdsa.PrivateKey
	prioritiser *Prioritiser
}

// Subscribe registers a prioritiser output subscriber function.
func (c *Component) Subscribe(fn func(context.Context, core.Duty, []TopicResult) error) {
	c.prioritiser.Subscribe(func(ctx context.Context, instance Instance, result *pbv1.PriorityResult) error {
		dutypb, ok := instance.(*pbv1.Duty)
		if !ok {
			return errors.New("invalid duty instance")
		}

		var results []TopicResult
		for _, topic := range result.Topics {
			result, err := topicResultFromProto(topic)
			if err != nil {
				return err
			}

			results = append(results, result)
		}

		return fn(ctx, core.DutyFromProto(dutypb), results)
	})
}

// Prioritise starts a new prioritisation instance for the provided duty and proposals or returns an error.
func (c *Component) Prioritise(ctx context.Context, duty core.Duty, proposals ...TopicProposal) error {
	instance, err := anypb.New(core.DutyToProto(duty))
	if err != nil {
		return errors.Wrap(err, "any proto duty")
	}

	var topics []*pbv1.PriorityTopicProposal
	for _, proposal := range proposals {
		proposalPB, err := topicProposalToProto(proposal)
		if err != nil {
			return err
		}

		topics = append(topics, proposalPB)
	}

	msg := &pbv1.PriorityMsg{
		Instance: instance,
		PeerId:   c.peerID.String(),
		Topics:   topics,
	}

	msg, err = signMsg(msg, c.privkey)
	if err != nil {
		return err
	}

	return c.prioritiser.Prioritise(ctx, msg)
}

// signMsg returns a copy of the proto message with a populated signature signed by the provided private key.
func signMsg(msg *pbv1.PriorityMsg, privkey *ecdsa.PrivateKey) (*pbv1.PriorityMsg, error) {
	clone := proto.Clone(msg).(*pbv1.PriorityMsg)
	clone.Signature = nil

	hash, err := hashProto(clone)
	if err != nil {
		return nil, err
	}

	clone.Signature, err = crypto.Sign(hash[:], privkey)
	if err != nil {
		return nil, errors.Wrap(err, "sign")
	}

	return clone, nil
}

// verifyMsgSig returns true if the message was signed by pubkey.
func verifyMsgSig(msg *pbv1.PriorityMsg, pubkey *ecdsa.PublicKey) (bool, error) {
	if msg.Signature == nil {
		return false, errors.New("empty signature")
	}

	clone := proto.Clone(msg).(*pbv1.QBFTMsg)
	clone.Signature = nil
	hash, err := hashProto(clone)
	if err != nil {
		return false, err
	}

	actual, err := crypto.SigToPub(hash[:], msg.Signature)
	if err != nil {
		return false, errors.Wrap(err, "sig to pub")
	}

	if !pubkey.Equal(actual) {
		return false, nil
	}

	return true, nil
}

// newMsgVerifier returns a function that verifies message signatures using peer public keys.
func newMsgVerifier(peers []peer.ID) (func(msg *pbv1.PriorityMsg) error, error) {
	// Extract peer pubkeys.
	keys := make(map[string]*ecdsa.PublicKey)
	for _, p := range peers {
		pk, err := p2p.PeerIDToKey(p)
		if err != nil {
			return nil, err
		}
		keys[p.String()] = pk
	}

	return func(msg *pbv1.PriorityMsg) error {
		key, ok := keys[msg.PeerId]
		if !ok {
			return errors.New("unknown peer id")
		}

		ok, err := verifyMsgSig(msg, key)
		if err != nil {
			return err
		} else if !ok {
			return errors.New("invalid signature")
		}

		return nil
	}, nil
}

type consensusWrapper struct {
	consensus coreConsensus
}

func (c consensusWrapper) ProposePriority(ctx context.Context, instance Instance, result *pbv1.PriorityResult) error {
	duty, ok := instance.(*pbv1.Duty)
	if !ok {
		return errors.New("invalid instance duty")
	}

	return c.consensus.ProposePriority(ctx, core.DutyFromProto(duty), result)
}

func (c consensusWrapper) SubscribePriority(fn func(context.Context, Instance, *pbv1.PriorityResult) error) {
	c.consensus.SubscribePriority(func(ctx context.Context, duty core.Duty, result *pbv1.PriorityResult) error {
		return fn(ctx, core.DutyToProto(duty), result)
	})
}

// topicProposalToProto returns the proto version of the topic proposal.
func topicProposalToProto(p TopicProposal) (*pbv1.PriorityTopicProposal, error) {
	topic, err := anypb.New(structpb.NewStringValue(p.Topic))
	if err != nil {
		return nil, errors.Wrap(err, "anypb topic")
	}

	var priorities []*anypb.Any
	for _, priority := range p.Priorities {
		pb, err := anypb.New(structpb.NewStringValue(priority))
		if err != nil {
			return nil, errors.Wrap(err, "anypb priority")
		}

		priorities = append(priorities, pb)
	}

	return &pbv1.PriorityTopicProposal{
		Topic:      topic,
		Priorities: priorities,
	}, nil
}

// topicProposalToProto returns a topic proposal from the proto version.
func topicResultFromProto(p *pbv1.PriorityTopicResult) (TopicResult, error) {
	var topicVal *structpb.Value
	if err := p.Topic.UnmarshalTo(topicVal); err != nil {
		return TopicResult{}, errors.Wrap(err, "anypb topic")
	}

	topic, ok := topicVal.AsInterface().(string)
	if !ok {
		return TopicResult{}, errors.New("topic value not a string")
	}

	var priorities []ScoredPriority
	for _, scored := range p.Priorities {
		var prioVal *structpb.Value
		if err := scored.Priority.UnmarshalTo(prioVal); err != nil {
			return TopicResult{}, errors.Wrap(err, "anypb priority")
		}

		prio, ok := prioVal.AsInterface().(string)
		if !ok {
			return TopicResult{}, errors.New("topic value not a string")
		}

		priorities = append(priorities, ScoredPriority{
			Priority: prio,
			Score:    int(scored.Score),
		})
	}

	return TopicResult{
		Topic:      topic,
		Priorities: priorities,
	}, nil
}
