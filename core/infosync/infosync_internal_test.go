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
	proposerTimer := func(c *Component) []string {
		for _, proposal := range c.proposals() {
			if proposal.Topic == topicProposerTimer {
				return proposal.Priorities
			}
		}

		return nil
	}

	require.Equal(t, []string{"linear"}, proposerTimer(&Component{localLinear: true}))
	require.Equal(t, []string{"eager_dlinear"}, proposerTimer(&Component{localLinear: false}))
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
			name: "linear agreed",
			results: []priority.TopicResult{
				topicResult(topicVersion, "v2.0"),
				topicResult(topicProtocol, "/charon/consensus/qbft/2.0.0"),
				topicResult(topicProposerTimer, "linear"),
			},
			want: result{slot: 7, versions: []string{"v2.0"}, protocols: []protocol.ID{"/charon/consensus/qbft/2.0.0"}, linearProposerTimer: true},
		},
		{
			name: "default agreed",
			results: []priority.TopicResult{
				topicResult(topicVersion, "v2.0"),
				topicResult(topicProposerTimer, "eager_dlinear"),
			},
			want: result{slot: 7, versions: []string{"v2.0"}},
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
				topicResult("unknown", "linear"),
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

func TestLinearProposerTimer(t *testing.T) {
	c := &Component{localLinear: true}

	// Defaults to the default proposer timer before any round, regardless of the local feature.
	require.False(t, c.LinearProposerTimer(10))

	// Results apply from the slot after their sync slot.
	c.addResult(result{slot: 5, versions: []string{"v2.0"}, linearProposerTimer: true})
	require.False(t, c.LinearProposerTimer(5)) // Sync slot.
	require.True(t, c.LinearProposerTimer(6))
	require.True(t, c.LinearProposerTimer(100))

	// A later round switches back to the default timer.
	c.addResult(result{slot: 8, versions: []string{"v2.0"}, linearProposerTimer: false})
	require.True(t, c.LinearProposerTimer(8))
	require.False(t, c.LinearProposerTimer(9))
}

func TestAddResultKeepsChangesOnly(t *testing.T) {
	c := new(Component)

	c.addResult(result{slot: 5, versions: []string{"v2.0"}, protocols: []protocol.ID{"a"}})
	c.addResult(result{slot: 37, versions: []string{"v2.0"}, protocols: []protocol.ID{"a"}}) // Same as previous.
	c.addResult(result{slot: 69, versions: []string{"v2.0"}, protocols: []protocol.ID{"a"}, linearProposerTimer: true})
	c.addResult(result{slot: 101, versions: []string{"v2.0", "v2.1"}, protocols: []protocol.ID{"a"}, linearProposerTimer: true})

	require.Len(t, c.results, 3)
	require.Equal(t, []uint64{5, 69, 101}, []uint64{c.results[0].slot, c.results[1].slot, c.results[2].slot})
}
