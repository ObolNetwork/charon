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
	"math/rand"
	"sort"

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
	prioritySetsByTopic := make(map[string][][]string)
	for _, msg := range determineInput(msgs) {
		for _, topic := range msg.Topics {
			prioritySetsByTopic[topic.Topic] = append(prioritySetsByTopic[topic.Topic], topic.Priorities)
		}
	}

	// Calculate cluster wide resulting priorities by topic.
	var topicResults []*pbv1.PriorityTopic
	for topic, prioritySet := range prioritySetsByTopic {
		// Calculate overall score for all priorities in the topic
		// which effectively orders by count then by overall priority.
		var (
			scores        = make(map[string]int)
			allPriorities []string
		)
		for _, priorities := range prioritySet {
			for order, label := range priorities {
				if _, ok := scores[label]; !ok {
					allPriorities = append(allPriorities, label)
				}
				scores[label] += countWeight - order // Equivalent to ordering by count then by priority
			}
		}

		// Order by score decreasing
		sort.Slice(allPriorities, func(i, j int) bool {
			return scores[allPriorities[i]] > scores[allPriorities[j]]
		})

		// Extract scores with min required count.
		minScore := (minRequired - 1) * countWeight
		result := &pbv1.PriorityTopic{Topic: topic}
		for _, priority := range allPriorities {
			if scores[priority] <= minScore {
				continue
			}
			result.Priorities = append(result.Priorities, priority)
		}

		topicResults = append(topicResults, result)
	}

	// Order results by topic for deterministic output.
	sort.Slice(topicResults, func(i, j int) bool {
		return topicResults[i].Topic < topicResults[j].Topic
	})

	return &pbv1.PriorityResult{
		Msgs:   msgs,
		Topics: topicResults,
	}, nil
}

// determineInput returns a deterministic copy of the messages ordered
// by peer.
func determineInput(msgs []*pbv1.PriorityMsg) []*pbv1.PriorityMsg {
	resp := append([]*pbv1.PriorityMsg(nil), msgs...) // Copy to not mutate input param.
	sort.Slice(resp, func(i, j int) bool {
		return resp[i].PeerId < resp[j].PeerId
	})

	// TODO(corver): There is a proposal to remove this shuffling behaviour since:
	//  - It makes the protocol hard to spec
	//  - Flapping of priorities might be less desirable than than non-random tiebreakers.

	//nolint:gosec // Math rand used for deterministic behaviour.
	rand.New(rand.NewSource(resp[0].Slot)).Shuffle(len(resp), func(i, j int) {
		resp[i], resp[j] = resp[j], resp[i]
	})

	return resp
}

// validateMsgs returns an error if the messages are invalid such that:
//  - messages contain duplicate peers,
//  - messages do not contain identical slots,
//  - individual peers contain duplicate topics,
//  - individual topics contain duplicate priorities,
//  - individual topics contain more than 1000 priorities.
func validateMsgs(msgs []*pbv1.PriorityMsg) error {
	if len(msgs) == 0 {
		return errors.New("messages empty")
	}

	var (
		slot       int64
		dedupPeers = newDeduper[string]() // Peers may not be duplicated
	)
	for _, msg := range msgs {
		if slot == 0 {
			slot = msg.Slot
		} else if msg.Slot != slot {
			return errors.New("mismatching slots")
		}
		if dedupPeers(msg.PeerId) {
			return errors.New("duplicate peer")
		}
		dedupTopics := newDeduper[string]() // Peers may not provide duplicate topics.
		for _, topic := range msg.Topics {
			if dedupTopics(msg.PeerId) {
				return errors.New("duplicate topic")
			} else if len(topic.Priorities) >= maxPriorities {
				return errors.New("max priority reached")
			}

			dedupPriority := newDeduper[string]() // Topics may not include duplicates priority.
			for _, priority := range topic.Priorities {
				if dedupPriority(priority) {
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
