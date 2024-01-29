// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package priority

import (
	"context"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/z"
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

// PrioritiesOnly returns the priorities without scores.
func (r TopicResult) PrioritiesOnly() []string {
	var resp []string
	for _, priority := range r.Priorities {
		resp = append(resp, priority.Priority)
	}

	return resp
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
func NewComponent(ctx context.Context, tcpNode host.Host, peers []peer.ID, minRequired int, sendFunc p2p.SendReceiveFunc,
	registerHandlerFunc p2p.RegisterHandlerFunc, consensus coreConsensus,
	exchangeTimeout time.Duration, privkey *k1.PrivateKey, deadlineFunc func(duty core.Duty) (time.Time, bool),
) (*Component, error) {
	verifier, err := newMsgVerifier(peers)
	if err != nil {
		return nil, err
	}

	deadliner := core.NewDeadliner(ctx, "priority", deadlineFunc)

	prioritiser := newInternal(tcpNode, peers, minRequired, sendFunc, registerHandlerFunc,
		consensus, verifier, exchangeTimeout, deadliner)

	return &Component{
		peerID:       tcpNode.ID(),
		prioritiser:  prioritiser,
		privkey:      privkey,
		deadlineFunc: deadlineFunc,
	}, nil
}

// Component wraps a prioritise protocol instance providing a
// friendly API (hiding the underlying protobuf types) and does signing.
type Component struct {
	peerID       peer.ID
	privkey      *k1.PrivateKey
	prioritiser  *Prioritiser
	deadlineFunc func(duty core.Duty) (time.Time, bool)
}

// Start starts a goroutine that cleans state.
func (c *Component) Start(ctx context.Context) {
	c.prioritiser.Start(ctx)
}

// Subscribe registers a prioritiser output subscriber function.
func (c *Component) Subscribe(fn func(context.Context, core.Duty, []TopicResult) error) {
	c.prioritiser.Subscribe(func(ctx context.Context, duty core.Duty, result *pbv1.PriorityResult) error {
		var results []TopicResult
		for _, topic := range result.Topics {
			result, err := topicResultFromProto(topic)
			if err != nil {
				return err
			}

			results = append(results, result)
		}

		return fn(ctx, duty, results)
	})
}

// Prioritise starts a new prioritisation instance for the provided duty and proposals or returns an error.
func (c *Component) Prioritise(ctx context.Context, duty core.Duty, proposals ...TopicProposal) error {
	var topics []*pbv1.PriorityTopicProposal
	for _, proposal := range proposals {
		proposalPB, err := topicProposalToProto(proposal)
		if err != nil {
			return err
		}

		topics = append(topics, proposalPB)
	}

	deadline, ok := c.deadlineFunc(duty)
	if !ok {
		return errors.New("duty already expired")
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	msg := &pbv1.PriorityMsg{
		Duty:   core.DutyToProto(duty),
		PeerId: c.peerID.String(),
		Topics: topics,
	}

	msg, err := signMsg(msg, c.privkey)
	if err != nil {
		return err
	}

	err = c.prioritiser.Prioritise(ctx, msg)
	if ctx.Err() != nil {
		return nil //nolint:nilerr // Context expiry is expected behaviour, return nil.
	} else if err != nil {
		return errors.Wrap(err, "prioritise", z.Any("duty", duty))
	}

	return nil
}

// signMsg returns a copy of the proto message with a populated signature signed by the provided private key.
func signMsg(msg *pbv1.PriorityMsg, privkey *k1.PrivateKey) (*pbv1.PriorityMsg, error) {
	clone := proto.Clone(msg).(*pbv1.PriorityMsg)
	clone.Signature = nil

	hash, err := hashProto(clone)
	if err != nil {
		return nil, err
	}

	clone.Signature, err = k1util.Sign(privkey, hash[:])
	if err != nil {
		return nil, errors.Wrap(err, "sign")
	}

	return clone, nil
}

// verifyMsgSig returns true if the message was signed by pubkey.
func verifyMsgSig(msg *pbv1.PriorityMsg, pubkey *k1.PublicKey) (bool, error) {
	if msg.Signature == nil {
		return false, errors.New("empty signature")
	}

	clone := proto.Clone(msg).(*pbv1.PriorityMsg)
	clone.Signature = nil
	hash, err := hashProto(clone)
	if err != nil {
		return false, err
	}

	actual, err := k1util.Recover(hash[:], msg.Signature)
	if err != nil {
		return false, errors.Wrap(err, "sig to pub")
	}

	if !pubkey.IsEqual(actual) {
		return false, nil
	}

	return true, nil
}

// newMsgVerifier returns a function that verifies message signatures using peer public keys.
func newMsgVerifier(peers []peer.ID) (func(msg *pbv1.PriorityMsg) error, error) {
	// Extract peer pubkeys.
	keys := make(map[string]*k1.PublicKey)
	for _, p := range peers {
		pk, err := p2p.PeerIDToKey(p)
		if err != nil {
			return nil, err
		}
		keys[p.String()] = pk
	}

	return func(msg *pbv1.PriorityMsg) error {
		if msg == nil || msg.Duty == nil {
			return errors.New("invalid priority msg proto fields", z.Any("msg", msg))
		}

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
	if p == nil {
		return TopicResult{}, errors.New("priority topic result proto cannot be nil")
	}

	topicVal := new(structpb.Value)
	if err := p.Topic.UnmarshalTo(topicVal); err != nil {
		return TopicResult{}, errors.Wrap(err, "anypb topic")
	}

	topic, ok := topicVal.AsInterface().(string)
	if !ok {
		return TopicResult{}, errors.New("topic value not a string")
	}

	var priorities []ScoredPriority
	for _, scored := range p.Priorities {
		prioVal := new(structpb.Value)
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
