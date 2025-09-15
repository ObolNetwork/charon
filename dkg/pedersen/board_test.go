// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pedersen_test

import (
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/drand/kyber"
	kdkg "github.com/drand/kyber/share/dkg"
	"github.com/drand/kyber/util/random"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg/bcast"
	"github.com/obolnetwork/charon/dkg/pedersen"
	"github.com/obolnetwork/charon/testutil"
)

func TestBoard(t *testing.T) {
	const n = 3

	var (
		secrets  []*k1.PrivateKey
		tcpNodes []host.Host
		peers    []peer.ID
		boards   []*pedersen.Board
		configs  []*pedersen.Config
		peerMap  = make(map[peer.ID]cluster.NodeIdx)
		session  = testutil.RandomArray32()
	)

	// Create secretes and libp2p nodes
	for i := range n {
		secret, err := k1.GeneratePrivateKey()
		require.NoError(t, err)

		secrets = append(secrets, secret)

		tcpNode := testutil.CreateHostWithIdentity(t, testutil.AvailableAddr(t), secret)
		t.Cleanup(func() { tcpNode.Close() })

		tcpNodes = append(tcpNodes, tcpNode)

		peers = append(peers, tcpNode.ID())
		peerMap[tcpNode.ID()] = cluster.NodeIdx{PeerIdx: i, ShareIdx: i + 1}
	}

	// Connect peers
	for i := range n {
		for j := range n {
			tcpNodes[i].Peerstore().AddAddrs(tcpNodes[j].ID(), tcpNodes[j].Addrs(), peerstore.PermanentAddrTTL)
		}
	}

	// Create boards
	for i := range n {
		bc := bcast.New(tcpNodes[i], peers, secrets[i])
		logCtx := log.WithCtx(t.Context(), z.Int("node", i))
		config := pedersen.NewConfig(peers[i], peerMap, n-1, session[:])
		configs = append(configs, config)
		board := pedersen.NewBoard(logCtx, tcpNodes[i], config, bc)
		boards = append(boards, board)
	}

	t.Run("bcast node pubkey", func(t *testing.T) {
		for i := range n {
			board := boards[i]
			pubKey := makePubKey(configs[i].Suite)
			pubKeyBytes, err := pubKey.MarshalBinary()
			require.NoError(t, err)

			err = board.BroadcastNodePubKey(t.Context(), pubKeyBytes)
			require.NoError(t, err)
		}

		peerPubKeys := make(map[peer.ID][]byte)

		for i := range n {
			board := boards[i]
			for range n { // each board should receive n pubkeys
				ppk := <-board.IncomingNodePubKeys()

				pk, exist := peerPubKeys[ppk.PeerID]
				if exist {
					require.Equal(t, pk, ppk.PubKey)
				} else {
					peerPubKeys[ppk.PeerID] = ppk.PubKey
				}
			}
		}

		require.Len(t, peerPubKeys, n)
	})

	t.Run("bcast validator pubkey share", func(t *testing.T) {
		for i := range n {
			board := boards[i]
			pubKey := makePubKey(configs[i].Suite)
			pubKeyBytes, err := pubKey.MarshalBinary()
			require.NoError(t, err)

			err = board.BroadcastValidatorPubKeyShare(t.Context(), pubKeyBytes)
			require.NoError(t, err)
		}

		validatorPubKeyShares := make(map[peer.ID][]byte)

		for i := range n {
			board := boards[i]
			for range n { // each board should receive n pubkeys
				ppk := <-board.IncomingValidatorPubKeyShares()

				pk, exist := validatorPubKeyShares[ppk.PeerID]
				if exist {
					require.Equal(t, pk, ppk.PubKey)
				} else {
					validatorPubKeyShares[ppk.PeerID] = ppk.PubKey
				}
			}
		}

		require.Len(t, validatorPubKeyShares, n)
	})

	t.Run("deal_bundle", func(t *testing.T) {
		for i := range n {
			dealBundle := kdkg.DealBundle{
				DealerIndex: uint32(i),
				Deals: []kdkg.Deal{
					{
						ShareIndex:     1,
						EncryptedShare: []byte{1, 2, 3},
					},
				},
				Public: []kyber.Point{
					randomPoint(t),
				},
				SessionID: []byte("sessionID"),
				Signature: []byte{13, 14, 15},
			}

			boards[i].PushDeals(&dealBundle)
		}

		for i := range n {
			received := <-boards[i].IncomingDeal()
			require.Len(t, received.Deals, 1)
			require.NotEqual(t, uint32(i), received.DealerIndex)
			require.Equal(t, []byte("sessionID"), received.SessionID)
			require.Equal(t, []byte{13, 14, 15}, received.Signature)
		}

		for i := range n {
			require.Empty(t, boards[i].IncomingResponse())
			require.Empty(t, boards[i].IncomingJustification())
		}
	})

	t.Run("response_bundle", func(t *testing.T) {
		for i := range n {
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

			boards[i].PushResponses(&responseBundle)
		}

		for i := range n {
			received := <-boards[i].IncomingResponse()
			require.Len(t, received.Responses, 1)
			require.NotEqual(t, uint32(i), received.ShareIndex)
			require.Equal(t, []byte("sessionID"), received.SessionID)
			require.Equal(t, []byte{23, 24, 25}, received.Signature)
		}

		for i := range n {
			require.Empty(t, boards[i].IncomingDeal())
			require.Empty(t, boards[i].IncomingJustification())
		}
	})

	t.Run("justification_bundle", func(t *testing.T) {
		for i := range n {
			justificationBundle := kdkg.JustificationBundle{
				DealerIndex: uint32(i),
				Justifications: []kdkg.Justification{
					{
						ShareIndex: 1,
						Share:      randomScalar(t),
					},
				},
				SessionID: []byte("sessionID"),
				Signature: []byte{33, 34, 35},
			}

			boards[i].PushJustifications(&justificationBundle)
		}

		for i := range n {
			received := <-boards[i].IncomingJustification()
			require.Len(t, received.Justifications, 1)
			require.NotEqual(t, uint32(i), received.DealerIndex)
			require.Equal(t, []byte("sessionID"), received.SessionID)
			require.Equal(t, []byte{33, 34, 35}, received.Signature)
		}

		for i := range n {
			require.Empty(t, boards[i].IncomingDeal())
			require.Empty(t, boards[i].IncomingResponse())
		}
	})
}

func makePubKey(suite kdkg.Suite) kyber.Point {
	private := suite.Scalar().Pick(random.New())
	public := suite.Point().Mul(private, nil)

	return public
}
