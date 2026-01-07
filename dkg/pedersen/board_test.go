// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pedersen_test

import (
	"testing"

	"github.com/drand/kyber"
	kdkg "github.com/drand/kyber/share/dkg"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg/pedersen"
	"github.com/obolnetwork/charon/testutil"
)

func TestBoard(t *testing.T) {
	const (
		numNodes  = 4
		threshold = 3
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

	t.Run("bcast node pubkeys", func(t *testing.T) {
		for i := range nodes {
			board := nodes[i].Board
			pubKey := pedersen.RandomPoint(t)
			pubKeyBytes, err := pubKey.MarshalBinary()
			require.NoError(t, err)

			pubKeyShare := pedersen.RandomPoint(t)
			pubKeyShareBytes, err := pubKeyShare.MarshalBinary()
			require.NoError(t, err)

			err = board.BroadcastNodePubKeyWithShares(t.Context(), pubKeyBytes, [][]byte{pubKeyShareBytes})
			require.NoError(t, err)
		}

		peerPubKeys := make(map[peer.ID][]byte)

		for i := range nodes {
			board := nodes[i].Board
			for range nodes { // each board should receive n pubkeys
				ppk := <-board.IncomingNodePubKeys()

				pk, exist := peerPubKeys[ppk.PeerID]
				if exist {
					require.Equal(t, pk, ppk.PubKey)
					require.Len(t, ppk.PubKeyShares, 1)
				} else {
					peerPubKeys[ppk.PeerID] = ppk.PubKey
				}
			}
		}

		require.Len(t, peerPubKeys, numNodes)
	})

	t.Run("bcast validator pubkey share", func(t *testing.T) {
		for i := range nodes {
			board := nodes[i].Board
			pubKey := pedersen.RandomPoint(t)
			pubKeyBytes, err := pubKey.MarshalBinary()
			require.NoError(t, err)

			err = board.BroadcastValidatorPubKeyShare(t.Context(), pubKeyBytes)
			require.NoError(t, err)
		}

		validatorPubKeyShares := make(map[peer.ID][]byte)

		for i := range nodes {
			board := nodes[i].Board
			for range nodes { // each board should receive n pubkeys
				ppk := <-board.IncomingValidatorPubKeyShares()

				pk, exist := validatorPubKeyShares[ppk.PeerID]
				if exist {
					require.Equal(t, pk, ppk.ValidatorPubKey)
				} else {
					validatorPubKeyShares[ppk.PeerID] = ppk.ValidatorPubKey
				}
			}
		}

		require.Len(t, validatorPubKeyShares, numNodes)
	})

	t.Run("deal_bundle", func(t *testing.T) {
		for i := range nodes {
			dealBundle := kdkg.DealBundle{
				DealerIndex: uint32(i),
				Deals: []kdkg.Deal{
					{
						ShareIndex:     1,
						EncryptedShare: []byte{1, 2, 3},
					},
				},
				Public: []kyber.Point{
					pedersen.RandomPoint(t),
				},
				SessionID: []byte("sessionID"),
				Signature: []byte{13, 14, 15},
			}

			nodes[i].Board.PushDeals(&dealBundle)
		}

		for i := range nodes {
			received := <-nodes[i].Board.IncomingDeal()
			require.Len(t, received.Deals, 1)
			require.Equal(t, []byte("sessionID"), received.SessionID)
			require.Equal(t, []byte{13, 14, 15}, received.Signature)
		}

		for i := range nodes {
			require.Empty(t, nodes[i].Board.IncomingResponse())
			require.Empty(t, nodes[i].Board.IncomingJustification())
		}
	})

	t.Run("response_bundle", func(t *testing.T) {
		for i := range nodes {
			responseBundle := kdkg.ResponseBundle{
				ShareIndex: uint32(i),
				Responses: []kdkg.Response{
					{
						DealerIndex: 1,
						Status:      true,
					},
				},
				SessionID: []byte("sessionID"),
				Signature: []byte{23, 24, 25},
			}

			nodes[i].Board.PushResponses(&responseBundle)
		}

		for i := range nodes {
			received := <-nodes[i].Board.IncomingResponse()
			require.Len(t, received.Responses, 1)
			require.Equal(t, []byte("sessionID"), received.SessionID)
			require.Equal(t, []byte{23, 24, 25}, received.Signature)
		}

		for i := range nodes {
			require.Empty(t, nodes[i].Board.IncomingDeal())
			require.Empty(t, nodes[i].Board.IncomingJustification())
		}
	})

	t.Run("justification_bundle", func(t *testing.T) {
		for i := range nodes {
			justificationBundle := kdkg.JustificationBundle{
				DealerIndex: uint32(i),
				Justifications: []kdkg.Justification{
					{
						ShareIndex: 1,
						Share:      pedersen.RandomScalar(t),
					},
				},
				SessionID: []byte("sessionID"),
				Signature: []byte{33, 34, 35},
			}

			nodes[i].Board.PushJustifications(&justificationBundle)
		}

		for i := range nodes {
			received := <-nodes[i].Board.IncomingJustification()
			require.Len(t, received.Justifications, 1)
			require.Equal(t, []byte("sessionID"), received.SessionID)
			require.Equal(t, []byte{33, 34, 35}, received.Signature)
		}

		for i := range nodes {
			require.Empty(t, nodes[i].Board.IncomingDeal())
			require.Empty(t, nodes[i].Board.IncomingResponse())
		}
	})
}
