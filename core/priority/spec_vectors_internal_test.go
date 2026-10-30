// Copyright © 2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package priority

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/testutil/specvectors"
)

// This file runs the spec conformance suites that need this package's unexported
// functions: calculateResult, and this package's own hashProto.
//
// Note that this hashProto is NOT interchangeable with the consensus package's.
// Priority hashes the `Any` wrapper of a topic or priority, type URL included
// (see calculateResult), while consensus unwraps and hashes the inner message
// and its hashProto rejects an Any outright. The any_string vectors belong here
// for that reason: passing them to the consensus hasher would error.

// TestSpecAnyStringHashing pins the hash of an `Any`-wrapped string, which is how
// priority topics and priorities are carried. The type URL is inside the hash, so
// an implementation that hashed the bare string would agree on nothing.
func TestSpecAnyStringHashing(t *testing.T) {
	var suite struct {
		AnyString []struct {
			Name  string `json:"name"`
			Input struct {
				StringValue string `json:"string_value"`
			} `json:"input"`
			EncodingHex string `json:"encoding_hex"`
			HashHex     string `json:"hash_hex"`
		} `json:"any_string"`
	}
	specvectors.Load(t, "qbft_hashing", &suite)
	require.NotEmpty(t, suite.AnyString)

	for _, tt := range suite.AnyString {
		t.Run(tt.Name, func(t *testing.T) {
			wrapped, err := anypb.New(structpb.NewStringValue(tt.Input.StringValue))
			require.NoError(t, err)

			encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(wrapped)
			require.NoError(t, err)
			require.Equal(t, tt.EncodingHex, hex.EncodeToString(encoded))

			hash, err := hashProto(wrapped)
			require.NoError(t, err)
			require.Equal(t, tt.HashHex, hex.EncodeToString(hash[:]))
		})
	}
}

// TestSpecPriorityScoring replays the spec's scoring table through
// calculateResult. The expected values were transcribed from this package's own
// TestCalculateResults, so this is a regression test against the published
// protocol rather than a second copy of that table.
func TestSpecPriorityScoring(t *testing.T) {
	var suite struct {
		Cases []struct {
			Name  string `json:"name"`
			Input struct {
				Slot         uint64 `json:"slot"`
				MinRequired  int    `json:"min_required"`
				Topic        string `json:"topic"`
				IgnoredTopic string `json:"ignored_topic"`
				Peers        []struct {
					PeerID     string   `json:"peer_id"`
					Priorities []string `json:"priorities"`
				} `json:"peers"`
			} `json:"input"`
			Result []struct {
				Priority string `json:"priority"`
				Score    int64  `json:"score"`
			} `json:"result"`
		} `json:"cases"`
	}
	specvectors.Load(t, "priority_scoring", &suite)
	require.NotEmpty(t, suite.Cases)

	for _, tt := range suite.Cases {
		t.Run(tt.Name, func(t *testing.T) {
			var msgs []*pbv1.PriorityMsg
			for _, peer := range tt.Input.Peers {
				msgs = append(msgs, &pbv1.PriorityMsg{
					Duty:   &pbv1.Duty{Slot: tt.Input.Slot},
					PeerId: peer.PeerID,
					Topics: []*pbv1.PriorityTopicProposal{
						topicProposal(t, tt.Input.Topic, peer.Priorities),
						// Proposed by every peer with no priorities, and required
						// to appear in the result with an empty list.
						topicProposal(t, tt.Input.IgnoredTopic, nil),
					},
				})
			}

			result, err := calculateResult(msgs, tt.Input.MinRequired)
			require.NoError(t, err)

			scored := topicResult(t, result, tt.Input.Topic)
			require.Len(t, scored, len(tt.Result))

			for i, want := range tt.Result {
				require.Equal(t, want.Priority, stringOf(t, scored[i].GetPriority()))
				require.Equal(t, want.Score, scored[i].GetScore())
			}

			require.Empty(t, topicResult(t, result, tt.Input.IgnoredTopic),
				"the ignored topic must be present with no priorities")
		})
	}
}

func topicProposal(t *testing.T, topic string, priorities []string) *pbv1.PriorityTopicProposal {
	t.Helper()

	wrapped, err := anypb.New(structpb.NewStringValue(topic))
	require.NoError(t, err)

	proposal := &pbv1.PriorityTopicProposal{Topic: wrapped}

	for _, priority := range priorities {
		value, err := anypb.New(structpb.NewStringValue(priority))
		require.NoError(t, err)

		proposal.Priorities = append(proposal.Priorities, value)
	}

	return proposal
}

// topicResult returns the scored priorities for one topic, failing the test if
// the topic is absent from the result. Absence is its own failure rather than an
// empty return, since "no priorities met the threshold" and "the topic was
// dropped" are different outcomes.
func topicResult(t *testing.T, result *pbv1.PriorityResult, topic string) []*pbv1.PriorityScoredResult {
	t.Helper()

	for _, candidate := range result.GetTopics() {
		if stringOf(t, candidate.GetTopic()) == topic {
			return candidate.GetPriorities()
		}
	}

	require.Failf(t, "topic missing from result", "topic %q", topic)

	return nil
}

func stringOf(t *testing.T, value *anypb.Any) string {
	t.Helper()

	inner, err := value.UnmarshalNew()
	require.NoError(t, err)

	structValue, ok := inner.(*structpb.Value)
	require.True(t, ok, "expected a structpb.Value")

	return structValue.GetStringValue()
}
