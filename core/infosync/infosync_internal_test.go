// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package infosync

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core/priority"
)

func TestAnyVersionAtLeast(t *testing.T) {
	tests := []struct {
		name     string
		versions []string
		want     bool
	}{
		{
			name:     "contains v1.11",
			versions: []string{"v1.11", "v1.10", "v1.9"},
			want:     true,
		},
		{
			name:     "only older versions",
			versions: []string{"v1.10", "v1.9"},
			want:     false,
		},
		{
			name:     "future minor qualifies",
			versions: []string{"v1.20.3-dev", "v1.10"},
			want:     true,
		},
		{
			name:     "future major qualifies",
			versions: []string{"v2.0.0"},
			want:     true,
		},
		{
			name:     "pre-release qualifies",
			versions: []string{"v1.11.0-rc1"},
			want:     true,
		},
		{
			name:     "unparseable ignored",
			versions: []string{"garbage", "v1.10"},
			want:     false,
		},
		{
			name:     "empty stays off",
			versions: nil,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := anyVersionAtLeast(tt.versions, minSyncContributionV2Version)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestSyncContributionsSupported(t *testing.T) {
	c := new(Component)

	// Defaults to false (backwards-compatible single encoding) before any round.
	require.False(t, c.SyncContributionsSupported(10))

	c.addSyncContribResult(syncContribResult{slot: 5, enabled: true})
	require.False(t, c.SyncContributionsSupported(4)) // Before first result.
	require.True(t, c.SyncContributionsSupported(5))
	require.True(t, c.SyncContributionsSupported(100))

	// A later round downgrades (e.g. an old peer joined).
	c.addSyncContribResult(syncContribResult{slot: 8, enabled: false})
	require.True(t, c.SyncContributionsSupported(7))
	require.False(t, c.SyncContributionsSupported(8))
	require.False(t, c.SyncContributionsSupported(100))
}

func TestProposerTimerProposal(t *testing.T) {
	c := &Component{proposerTimer: "linear/1.5s/300ms"}

	var got []string

	for _, proposal := range c.proposals() {
		if proposal.Topic == topicProposerTimer {
			got = proposal.Priorities
		}
	}

	require.Equal(t, []string{"linear/1.5s/300ms"}, got)
}

func TestNewResult(t *testing.T) {
	topicResult := func(topic string, priorities ...string) priority.TopicResult {
		res := priority.TopicResult{Topic: topic}
		for _, prio := range priorities {
			res.Priorities = append(res.Priorities, priority.ScoredPriority{Priority: prio})
		}

		return res
	}

	tests := []struct {
		name    string
		results []priority.TopicResult
		want    result
	}{
		{
			name: "proposer timer agreed",
			results: []priority.TopicResult{
				topicResult(topicVersion, "v2.0"),
				topicResult(topicProtocol, "/charon/consensus/qbft/2.0.0"),
				topicResult(topicProposerTimer, "linear/1.5s/300ms"),
			},
			want: result{slot: 7, versions: []string{"v2.0"}, protocols: []protocol.ID{"/charon/consensus/qbft/2.0.0"}, proposerTimer: "linear/1.5s/300ms"},
		},
		{
			name: "below threshold, nothing agreed",
			results: []priority.TopicResult{
				topicResult(topicVersion, "v2.0"),
				topicResult(topicProposerTimer),
			},
			want: result{slot: 7, versions: []string{"v2.0"}},
		},
		{
			name: "topic missing, from peers without it",
			results: []priority.TopicResult{
				topicResult(topicVersion, "v2.0"),
			},
			want: result{slot: 7, versions: []string{"v2.0"}},
		},
		{
			name: "unknown topic ignored",
			results: []priority.TopicResult{
				topicResult(topicVersion, "v2.0"),
				topicResult("unknown", "linear/1.5s/300ms"),
			},
			want: result{slot: 7, versions: []string{"v2.0"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, newResult(7, tt.results))
		})
	}
}

func TestProposerTimer(t *testing.T) {
	c := &Component{proposerTimer: "linear/1.5s/300ms"}

	// None agreed before any round, regardless of the local proposal.
	require.Empty(t, c.ProposerTimer(10))

	// Results apply from the slot after their sync slot.
	c.addResult(result{slot: 5, versions: []string{"v2.0"}, proposerTimer: "linear/1.5s/300ms"})
	require.Empty(t, c.ProposerTimer(5)) // Sync slot.
	require.Equal(t, "linear/1.5s/300ms", c.ProposerTimer(6))
	require.Equal(t, "linear/1.5s/300ms", c.ProposerTimer(100))

	// A later round agrees on other inputs.
	c.addResult(result{slot: 8, versions: []string{"v2.0"}, proposerTimer: "linear/1.2s/400ms"})
	require.Equal(t, "linear/1.5s/300ms", c.ProposerTimer(8))
	require.Equal(t, "linear/1.2s/400ms", c.ProposerTimer(9))
}

func TestAddResultKeepsChangesOnly(t *testing.T) {
	c := new(Component)

	c.addResult(result{slot: 5, versions: []string{"v2.0"}, protocols: []protocol.ID{"a"}})
	c.addResult(result{slot: 37, versions: []string{"v2.0"}, protocols: []protocol.ID{"a"}}) // Same as previous.
	c.addResult(result{slot: 69, versions: []string{"v2.0"}, protocols: []protocol.ID{"a"}, proposerTimer: "linear/1.5s/300ms"})
	c.addResult(result{slot: 101, versions: []string{"v2.0", "v2.1"}, protocols: []protocol.ID{"a"}, proposerTimer: "linear/1.5s/300ms"})

	require.Len(t, c.results, 3)
	require.Equal(t, []uint64{5, 69, 101}, []uint64{c.results[0].slot, c.results[1].slot, c.results[2].slot})
}
