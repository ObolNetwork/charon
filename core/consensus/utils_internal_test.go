// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus

import (
	"testing"

	"github.com/hashicorp/go-version"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/stretchr/testify/require"
)

func TestParseProtocolID(t *testing.T) {
	v2, _ := version.NewVersion("2.0.0")
	v321, _ := version.NewVersion("3.2.1")

	tests := []struct {
		id      protocol.ID
		name    string
		version *version.Version
		error   string
	}{
		{
			id:      "/charon/consensus/qbft/2.0.0",
			name:    "qbft",
			version: v2,
		},
		{
			id:      "/charon/consensus/abft/3.2.1",
			name:    "abft",
			version: v321,
		},
		{
			id:    "/charon/other/qbft/2.0.0",
			error: "not a consensus protocol",
		},
		{
			id:    "/charon/consensus/incomplete",
			error: "wrong protocol ID format",
		},
		{
			id:    "/charon/consensus/obolbft/2.x.z",
			error: "failed to parse version",
		},
	}

	for _, tt := range tests {
		name, version, err := parseProtocolID(tt.id)
		if tt.error != "" {
			require.ErrorContains(t, err, tt.error)
		} else {
			require.NoError(t, err)
			require.Equal(t, tt.name, name)
			require.Equal(t, tt.version, version)
		}
	}
}

func TestSelectLatestProtocolID(t *testing.T) {
	protocols := []protocol.ID{
		"/charon/consensus/qbft/2.0.0",
		"/charon/consensus/hotstuff/1.0.0",
		"/charon/consensus/abft/3.2.1",
		"/charon/consensus/abft/2.1.0",
		"/charon/consensus/abft/1.0.0",
	}

	tests := []struct {
		name     string
		selected protocol.ID
	}{
		{
			name:     "hotstuff",
			selected: "/charon/consensus/hotstuff/1.0.0",
		},
		{
			name:     "abft",
			selected: "/charon/consensus/abft/3.2.1",
		},
		{
			name:     "unknown",
			selected: LastRestortProtocolID,
		},
	}

	for _, tt := range tests {
		selected := SelectLatestProtocolID(tt.name, protocols)
		require.Equal(t, tt.selected, selected)
	}
}

func TestListProtocolNames(t *testing.T) {
	protocols := []protocol.ID{
		"/charon/consensus/qbft/2.0.0",
		"/charon/consensus/hotstuff/1.0.0",
		"/charon/consensus/abft/3.2.1",
		"/charon/consensus/abft/2.1.0",
		"/charon/consensus/abft/1.0.0",
	}

	names, err := ListProtocolNames(protocols)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"qbft", "hotstuff", "abft"}, names)
}
