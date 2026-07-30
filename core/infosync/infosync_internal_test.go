// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package infosync

import (
	"testing"

	"github.com/stretchr/testify/require"
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
