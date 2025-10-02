// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pedersen_test

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg/pedersen"
	"github.com/obolnetwork/charon/testutil"
)

func TestRunDKG(t *testing.T) {
	const (
		threshold = 3
		numNodes  = 4
		numVals   = 2
	)

	var (
		peers   []peer.ID
		peerMap = make(map[peer.ID]cluster.NodeIdx)
		session = testutil.RandomArray32()
	)

	nodes := make([]*pedersen.TestNode, numNodes)
	for i := range numNodes {
		nodes[i] = pedersen.NewTestNode(t, i)
		peerMap[nodes[i].NodeHost.ID()] = nodes[i].NodeIdx
		peers = append(peers, nodes[i].NodeHost.ID())
	}

	pedersen.ConnectTestNodes(t, nodes)

	for i := range nodes {
		nodes[i].InitBoard(t, threshold, peers, peerMap, session[:])
	}

	// Running DKG
	group, gctx := errgroup.WithContext(t.Context())

	for n := range nodes {
		group.Go(func() error {
			shares, err := pedersen.RunDKG(gctx, nodes[n].Config, nodes[n].Board, numVals)
			nodes[n].Shares = shares

			return err
		})
	}

	err := group.Wait()
	require.NoError(t, err, "DKG failed on one or more nodes")

	pedersen.VerifyShares(t, nodes, numVals, threshold)
}
