// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package priority

import (
	"bytes"
	"sort"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/obolnetwork/charon/app/errors"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
)

const (
	maxPriorities = 1000          // maxPriorities defines the max priorities by topic.
	countWeight   = maxPriorities // Weight count more than relative priority.
)

// calculateResult is a deterministic function that returns the cluster wide
// priorities given the priorities of each peer. Priorities are included in the
// result if minRequired peers provided them and are ordered by number of peers
// then by overall priority.
func calculateResult(msgs []*pbv1.PriorityMsg, minRequired int) (*pbv1.PriorityResult, error) {
	if err := validateMsgs(msgs); err != nil {
		return nil, err
	}

	// Group all priority sets by topic
	proposalsByTopic := make(map[[32]byte][]*pbv1.PriorityTopicProposal)

	for _, msg := range sortInput(msgs) {
		for _, topic := range msg.GetTopics() {
			topicHash, err := hashProto(topic.GetTopic())
			if err != nil {
				return nil, err
			}

			proposalsByTopic[topicHash] = append(proposalsByTopic[topicHash], topic)
		}
	}

	// Calculate cluster wide resulting priorities by topic.
	var topicResults []*pbv1.PriorityTopicResult

	for _, proposals := range proposalsByTopic {
		// Calculate overall score for all priorities in the topic
		// which effectively orders by count then by overall priority.
		var (
			scores        = make(map[[32]byte]int)
			priorities    = make(map[[32]byte]*anypb.Any)
			allPriorities [][32]byte
		)

		for _, proposal := range proposals {
			for order, prio := range proposal.GetPriorities() {
				priority, err := hashProto(prio)
				if err != nil {
					return nil, err
				}

				if _, ok := scores[priority]; !ok {
					allPriorities = append(allPriorities, priority)
				}

				scores[priority] += countWeight - order // Equivalent to ordering by count then by priority
				priorities[priority] = prio
			}
		}

		// Order by score decreasing
		sort.Slice(allPriorities, func(i, j int) bool {
			return scores[allPriorities[i]] > scores[allPriorities[j]]
		})

		// Extract scores with min required count.
		minScore := (minRequired - 1) * countWeight
		result := &pbv1.PriorityTopicResult{Topic: proposals[0].GetTopic()}

		for _, priority := range allPriorities {
			score := scores[priority]
			if score <= minScore {
				continue
			}

			result.Priorities = append(result.Priorities, &pbv1.PriorityScoredResult{
				Priority: priorities[priority],
				Score:    int64(score),
			})
		}

		topicResults = append(topicResults, result)
	}

	ordered, err := orderTopicResults(topicResults)
	if err != nil {
		return nil, err
	}

	return &pbv1.PriorityResult{
		Msgs:   msgs,
		Topics: ordered,
	}, nil
}

// orderTopicResults returns ordered results by topic for deterministic output.
func orderTopicResults(values []*pbv1.PriorityTopicResult) ([]*pbv1.PriorityTopicResult, error) {
	type tuple struct {
		Hash  []byte
		Value *pbv1.PriorityTopicResult
	}

	var tuples []tuple

	for _, value := range values {
		hash, err := hashProto(value.GetTopic())
		if err != nil {
			return nil, err
		}

		tuples = append(tuples, tuple{
			Hash:  hash[:],
			Value: value,
		})
	}

	sort.Slice(tuples, func(i, j int) bool {
		return bytes.Compare(tuples[i].Hash, tuples[j].Hash) < 0
	})

	var resp []*pbv1.PriorityTopicResult
	for _, tuple := range tuples {
		resp = append(resp, tuple.Value)
	}

	return resp, nil
}

// sortInput returns a copy of the messages ordered
// by peer.
func sortInput(msgs []*pbv1.PriorityMsg) []*pbv1.PriorityMsg {
	resp := append([]*pbv1.PriorityMsg(nil), msgs...) // Copy to not mutate input param.
	sort.Slice(resp, func(i, j int) bool {
		return resp[i].GetPeerId() < resp[j].GetPeerId()
	})

	return resp
}

// validateMsgs returns an error if the messages are invalid such that:
//   - messages contain duplicate peers,
//   - messages do not contain identical slots,
//   - individual peers contain duplicate topics,
//   - individual topics contain duplicate priorities,
//   - individual topics contain more than 1000 priorities.
func validateMsgs(msgs []*pbv1.PriorityMsg) error {
	if len(msgs) == 0 {
		return errors.New("messages empty")
	}

	var (
		duty       *pbv1.Duty
		dedupPeers = newDeduper[string]() // Peers may not be duplicated
	)
	for _, msg := range msgs {
		if duty == nil {
			duty = msg.GetDuty()
		} else if !proto.Equal(duty, msg.GetDuty()) {
			return errors.New("mismatching duties")
		}

		if dedupPeers(msg.GetPeerId()) {
			return errors.New("duplicate peer")
		}

		dedupTopics := newDeduper[[32]byte]() // Peers may not provide duplicate topics.

		for _, topic := range msg.GetTopics() {
			topicHash, err := hashProto(topic.GetTopic())
			if err != nil {
				return err
			}

			if dedupTopics(topicHash) {
				return errors.New("duplicate topic")
			} else if len(topic.GetPriorities()) >= maxPriorities {
				return errors.New("max priority reached")
			}

			dedupPriority := newDeduper[[32]byte]() // Topics may not include duplicates priority.

			for _, priority := range topic.GetPriorities() {
				prioHash, err := hashProto(priority)
				if err != nil {
					return err
				}

				if dedupPriority(prioHash) {
					return errors.New("duplicate priority")
				}
			}
		}
	}

	return nil
}

// newDeduper returns a new generic deduplicater.
func newDeduper[T comparable]() func(t T) bool {
	duplicates := make(map[T]bool)

	return func(t T) bool {
		if duplicates[t] {
			return true
		}

		duplicates[t] = true

		return false
	}
}
