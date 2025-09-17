// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pedersen_test

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg/pedersen"
	"github.com/obolnetwork/charon/tbls"
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

	nodes := make([]*testNode, numNodes)
	for i := range numNodes {
		nodes[i] = newTestNode(t, i)
		peerMap[nodes[i].host.ID()] = nodes[i].idx
		peers = append(peers, nodes[i].host.ID())
	}

	connectTestNodes(t, nodes)

	for i := range nodes {
		nodes[i].initBoard(t, threshold, peers, peerMap, session[:])
	}

	// Running DKG
	group, gctx := errgroup.WithContext(t.Context())

	for n := range nodes {
		group.Go(func() error {
			shares, err := pedersen.RunDKG(gctx, nodes[n].config, nodes[n].board, numVals)
			nodes[n].shares = shares

			return err
		})
	}

	err := group.Wait()
	require.NoError(t, err, "DKG failed on one or more nodes")

	verifyShares(t, nodes, numVals, threshold)
}

func verifyShares(t *testing.T, nodes []*testNode, numVals, threshold int) {
	t.Helper()

	msg := []byte("data")

	for v := range numVals {
		var (
			sigs    []tbls.Signature
			pshares []tbls.PublicKey
			secrets = make(map[int]tbls.PrivateKey)
		)

		for _, node := range nodes {
			require.Len(t, node.shares, numVals)

			pubKeyShare := node.shares[v].PublicShares[node.idx.ShareIdx]
			sig, err := tbls.Sign(node.shares[v].SecretShare, msg)
			require.NoError(t, err)

			err = tbls.Verify(pubKeyShare, msg, sig)
			require.NoError(t, err)

			sigs = append(sigs, sig)
			pshares = append(pshares, pubKeyShare)
			secrets[node.idx.ShareIdx] = node.shares[v].SecretShare
		}

		aggSig, err := tbls.Aggregate(sigs)
		require.NoError(t, err)

		err = tbls.VerifyAggregate(pshares, aggSig, msg)
		require.NoError(t, err)

		recSecret, err := tbls.RecoverSecret(secrets, uint(len(nodes)), uint(threshold))
		require.NoError(t, err)

		sig, err := tbls.Sign(recSecret, msg)
		require.NoError(t, err)

		err = tbls.Verify(nodes[0].shares[v].PubKey, msg, sig)
		require.NoError(t, err)
	}
}
