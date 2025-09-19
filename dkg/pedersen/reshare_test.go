// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pedersen_test

import (
	"encoding/hex"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg/pedersen"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil"
)

func TestRunReshare(t *testing.T) {
	const (
		threshold = 3
		numNodes  = 4
		numVals   = 2
	)

	oldShares := make([][]*pedersen.Share, numNodes)
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
		oldShares[n] = make([]*pedersen.Share, numVals)
		for v := range numVals {
			oldShares[n][v] = &pedersen.Share{
				SecretShare: tbls.PrivateKey(mustDecodeHex(t, oldSecrets[n][v])),
				PubKey:      tbls.PublicKey(mustDecodeHex(t, oldPubKeys[v])),
			}
		}
	}

	var (
		peers   []peer.ID
		peerMap = make(map[peer.ID]cluster.NodeIdx)
		nodes   = make([]*testNode, numNodes)
	)

	for i := range numNodes {
		nodes[i] = newTestNode(t, i)
		peerMap[nodes[i].host.ID()] = nodes[i].idx
		peers = append(peers, nodes[i].host.ID())
	}

	connectTestNodes(t, nodes)

	session := testutil.RandomArray32()

	for i := range nodes {
		nodes[i].initBoard(t, threshold, peers, peerMap, session[:])
	}

	group, gctx := errgroup.WithContext(t.Context())

	for n := range nodes {
		group.Go(func() error {
			nodes[n].config.Reshare = &pedersen.ReshareConfig{TotalShares: numVals, NewThreshold: threshold}
			shares, err := pedersen.RunReshareDKG(gctx, nodes[n].config, nodes[n].board, oldShares[n])
			nodes[n].shares = shares

			return err
		})
	}

	err := group.Wait()
	require.NoError(t, err, "Reshare failed on one or more nodes")

	verifyShares(t, nodes, numVals, threshold)
	verifyDiff(t, nodes, oldShares, numVals)
}

func verifyDiff(t *testing.T, nodes []*testNode, oldShares [][]*pedersen.Share, numVals int) {
	t.Helper()

	for n := range nodes {
		dkgNodeShares := oldShares[n]
		reshareNodeShares := nodes[n].shares

		for v := range numVals {
			// Validator public keys should be the same after resharing
			require.Equal(t, dkgNodeShares[v].PubKey, reshareNodeShares[v].PubKey)

			// The secret shares should be different, because of resharing
			require.NotEqual(t, dkgNodeShares[v].SecretShare, reshareNodeShares[v].SecretShare)
		}
	}
}

func mustDecodeHex(t *testing.T, str string) []byte {
	t.Helper()

	b, err := hex.DecodeString(str)
	require.NoError(t, err)

	return b
}
