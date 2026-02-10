// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pedersen_test

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg/pedersen"
	"github.com/obolnetwork/charon/dkg/share"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil"
)

func TestRunReshare(t *testing.T) {
	const (
		threshold = 3
		numNodes  = 4
		numVals   = 2
	)

	oldShares := make([][]share.Share, numNodes)
	oldSecrets := [][]string{
		{
			"698bf874afad4b65057c63e4b75485dd4c08af60b7d32fd7aa5e70bfce619c35",
			"057a6d79a11cb6006dca3f4bdb05c5f4fffa828034d3049eeda012cd5678dd3a",
		},
		{
			"6de2b6df0b0cae8a79dd58bafe3f4e33dfb386bbabf84cf82d5a17f8d93659d0",
			"37a01478c20b44eeceb26e20bb6a99984121455e2781945ccbc1f312a988c50c",
		},
		{
			"1d1ca6859f85b74188be77774318203799cbbd53db4969862f66385791632159",
			"110bbe177f9595b7c8a432449b135fffe84be54941ea4efa14f16dd4cc53368e",
		},
		{
			"5f15160ec053601a989370299922abf321cc9b2f45c33d7fb082d1d9f6e7f2d2",
			"05ab11a9035925a38ed963bf83a1f13149380644840b9075c92e8312bed831c1",
		},
	}
	oldPubKeys := []string{
		"b1ff2b0be51638bf0a3f1d7cbebd09b53a19784a452fb006ba1c0984c19dfa64429102c65250866aab70a841fcf84725",
		"9530295879619a9d8cb25276c412f9443e98e4b117643579853a7c126cf98bcf263ccbd39f78786130e41d5b46ab29a1",
	}

	for n := range numNodes {
		oldShares[n] = make([]share.Share, numVals)
		for v := range numVals {
			oldShares[n][v] = share.Share{
				SecretShare: tbls.PrivateKey(pedersen.MustDecodeHex(t, oldSecrets[n][v])),
				PubKey:      tbls.PublicKey(pedersen.MustDecodeHex(t, oldPubKeys[v])),
			}
		}
	}

	var (
		peers   []peer.ID
		peerMap = make(map[peer.ID]cluster.NodeIdx)
		nodes   = make([]*pedersen.TestNode, numNodes)
	)

	for i := range numNodes {
		nodes[i] = pedersen.NewTestNode(t, i)
		peerMap[nodes[i].NodeHost.ID()] = nodes[i].NodeIdx
		peers = append(peers, nodes[i].NodeHost.ID())
	}

	pedersen.ConnectTestNodes(t, nodes)

	session := testutil.RandomArray32()

	for i := range nodes {
		nodes[i].InitBoard(t, threshold, peers, peerMap, session[:])
	}

	group, gctx := errgroup.WithContext(t.Context())

	// Extract expected validator public keys from old shares
	// All nodes should have the same validator public keys
	var expectedValidatorPubKeys []tbls.PublicKey
	if len(oldShares) > 0 && len(oldShares[0]) > 0 {
		expectedValidatorPubKeys = make([]tbls.PublicKey, len(oldShares[0]))
		for i, share := range oldShares[0] {
			expectedValidatorPubKeys[i] = share.PubKey
		}
	}

	for n := range nodes {
		group.Go(func() error {
			nodes[n].Config.Reshare = &pedersen.ReshareConfig{TotalShares: numVals, NewThreshold: threshold}
			shares, err := pedersen.RunReshareDKG(gctx, nodes[n].Config, nodes[n].Board, oldShares[n], expectedValidatorPubKeys)
			nodes[n].Shares = shares

			return err
		})
	}

	err := group.Wait()
	require.NoError(t, err, "Reshare failed on one or more nodes")

	pedersen.VerifyShares(t, nodes, numVals, threshold)
	pedersen.VerifyDiff(t, nodes, oldShares, numVals)
}
