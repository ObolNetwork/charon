// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pedersen_test

import (
	"testing"
	"time"

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

	phaseDuration := 3 * time.Second
	config := pedersen.NewConfig("peer1", peerMap, 2, []byte("session1"), phaseDuration, nil)
	require.Equal(t, phaseDuration, config.PhaseDuration)
	require.EqualValues(t, "peer1", config.ThisPeerID)
	require.Equal(t, peerMap, config.PeerMap)
	require.Equal(t, 2, config.Threshold)
	require.Equal(t, []byte("session1"), config.SessionID)
	require.Equal(t, 3, config.Nodes())
	require.NotNil(t, config.Suite)

	newPeers := []peer.ID{peer.ID("peer21"), peer.ID("peer22"), peer.ID("peer23"), peer.ID("peer24")}
	oldPeers := []peer.ID{peer.ID("peer2"), peer.ID("peer3")}

	reshareConfig := pedersen.NewReshareConfig(2, 3, newPeers, oldPeers)
	require.Equal(t, 2, reshareConfig.TotalShares)
	require.Equal(t, 3, reshareConfig.NewThreshold)
	require.Equal(t, newPeers, reshareConfig.AddedPeers)
	require.Equal(t, oldPeers, reshareConfig.RemovedPeers)

	config2 := pedersen.NewConfig("peer21", peerMap, 2, []byte("session2"), phaseDuration, reshareConfig)
	require.Equal(t, reshareConfig, config2.Reshare)

	idx, err := config.ThisNodeIndex()
	require.NoError(t, err)
	require.Equal(t, 0, idx)
}
