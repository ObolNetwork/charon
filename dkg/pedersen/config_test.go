// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pedersen_test

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg/pedersen"
)

func TestNewConfig(t *testing.T) {
	peerMap := map[peer.ID]cluster.NodeIdx{
		"peer1": {PeerIdx: 0, ShareIdx: 1},
		"peer2": {PeerIdx: 1, ShareIdx: 2},
		"peer3": {PeerIdx: 2, ShareIdx: 3},
	}

	config := pedersen.NewConfig("peer1", peerMap, 2, []byte("session1"))
	require.EqualValues(t, "peer1", config.ThisPeerID)
	require.Equal(t, peerMap, config.PeerMap)
	require.Equal(t, 2, config.Threshold)
	require.Equal(t, []byte("session1"), config.SessionID)
	require.Equal(t, 3, config.Nodes())
	require.NotNil(t, config.Suite)
}
