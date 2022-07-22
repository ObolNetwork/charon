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

// calculateResults is a deterministic function that returns the cluster wide
// priorities given the priorities of each peer. Priorities are included in the
// result if minRequired peers provided them and are ordered by number of peers
// then by overall priority.
//
// Peer messages are validated such that
// they do not contain duplicate peers, they contain identical slots,
// individual peers may not contain duplicate topics, individual topics
// may not contain duplicate priorities or more than 1000 priorities.
//nolint:gocognit // Mostly just map reduce.
func calculateResults(msgs []*pbv1.PriorityMsg, minRequired int) (*pbv1.PriorityResult, error) {
	// Prepare deterministic input messages:
	//  - validate
	//  - then sort by peer
	//  - then shuffle by slot (for random tiebreaker)
	var (
		slot       int64
		input      []*pbv1.PriorityMsg
		dedupPeers = newDeduper[string]("peer") // Peers may not be duplicated

	)
	for _, msg := range msgs {
		if slot == 0 {
			slot = msg.Slot
		} else if msg.Slot != slot {
			return nil, errors.New("mismatching slots")
		}
		if err := dedupPeers(msg.PeerId); err != nil {
			return nil, err
		}
		dedupTopics := newDeduper[string]("topic") // Peers may not provide duplicate topics.
		for _, topic := range msg.Topics {
			if err := dedupTopics(topic.Topic); err != nil {
				return nil, err
			} else if len(topic.Priorities) >= maxPriorities {
				return nil, errors.New("max priority reached")
			}

			dedupPriority := newDeduper[string]("priority") // Topics may not include duplicates priority.
			for _, priority := range topic.Priorities {
				if err := dedupPriority(priority); err != nil {
					return nil, err
				}
			}
		}

		input = append(input, msg) // Copy to not mutate input param.
	}
	sort.Slice(input, func(i, j int) bool {
		return input[i].PeerId < input[j].PeerId
	})
	//nolint:gosec // Math rand used for deterministic behaviour.
	rand.New(rand.NewSource(slot)).Shuffle(len(input), func(i, j int) {
		input[i], input[j] = input[j], input[i]
	})

	// Group all priority sets by topic
	prioritySetsByTopic := make(map[string][][]string)
	for _, msg := range input {
		for _, topic := range msg.Topics {
			prioritySetsByTopic[topic.Topic] = append(prioritySetsByTopic[topic.Topic], topic.Priorities)
		}
	}

	// Calculate cluster wide resulting priorities by topic.
	var topicResults []*pbv1.PriorityTopic
	for topic, prioritySet := range prioritySetsByTopic {
		if len(prioritySet) < minRequired {
			// Shortcut since min require cannot be met.
			continue
		}

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
		Msgs:   input,
		Topics: topicResults,
	}, nil
}

// newDeduper returns a new generic named deduplicater.
func newDeduper[T comparable](name string) func(t T) error {
	duplicates := make(map[T]bool)

	return func(t T) error {
		if duplicates[t] {
			return errors.New("duplicate " + name)
		}
		duplicates[t] = true

		return nil
	}
}
