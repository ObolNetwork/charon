// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"
	"sync"
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	pb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/testutil"
)

func TestBcastCallback(t *testing.T) {
	const (
		n         = 4
		threshold = 3
		numVals   = 2
	)

	var (
		ctx   = context.Background()
		peers []peer.ID
	)

	// Create libp2p peers
	peerMap := make(map[peer.ID]cluster.NodeIdx)
	for i := 0; i < n; i++ {
		secret, err := k1.GeneratePrivateKey()
		require.NoError(t, err)

		tcpNode := testutil.CreateHostWithIdentity(t, testutil.AvailableAddr(t), secret)
		peers = append(peers, tcpNode.ID())
		peerMap[tcpNode.ID()] = cluster.NodeIdx{
			PeerIdx:  i,
			ShareIdx: i + 1,
		}
	}

	var (
		round1CastsRecv = make(chan *pb.FrostRound1Casts, len(peerMap))
		round2CastsRecv = make(chan *pb.FrostRound2Casts, len(peerMap))

		mu               sync.Mutex
		dedupRound1Casts = make(map[peer.ID]bool)
		dedupRound2Casts = make(map[peer.ID]bool)
	)

	tests := []struct {
		name                 string
		round1Cast           *pb.FrostRound1Cast
		round2Cast           *pb.FrostRound2Cast
		errorMsg             string
		invalidRoundCast     bool
		invalidRound1CastMsg bool
		invalidRound2CastMsg bool
	}{
		{
			name: "invalid round 1 sourceID",
			round1Cast: &pb.FrostRound1Cast{
				Key: &pb.FrostMsgKey{
					SourceId: 2, // Invalid SourceID since peers[0].ShareIdx is 1
				},
			},
			errorMsg: "invalid round 1 cast source ID",
		},
		{
			name: "invalid round 1 cast target ID",
			round1Cast: &pb.FrostRound1Cast{
				Key: &pb.FrostMsgKey{
					SourceId: 1,
					TargetId: 1, // Invalid targetID since bcast targetID should always be 0
				},
			},
			errorMsg: "invalid round 1 cast target ID",
		},
		{
			name: "invalid round 1 cast validator index",
			round1Cast: &pb.FrostRound1Cast{
				Key: &pb.FrostMsgKey{
					SourceId: 1,
					TargetId: 0,
					ValIdx:   3, // Invalid ValIdx since it should be less than numVals
				},
			},
			errorMsg: "invalid round 1 cast validator index",
		},
		{
			name: "invalid round 1 commitments",
			round1Cast: &pb.FrostRound1Cast{
				Key: &pb.FrostMsgKey{
					ValIdx:   0,
					SourceId: 1,
					TargetId: 0,
				},
				Commitments: nil, // Invalid since len(commitments) should be equal to threshold
			},
			errorMsg: "invalid amount of commitments in round 1",
		},
		{
			name: "invalid round 2 cast source ID",
			round2Cast: &pb.FrostRound2Cast{
				Key: &pb.FrostMsgKey{
					SourceId: 2, // Invalid SourceID since peers[0].ShareIdx is 1
				},
			},
			errorMsg: "invalid round 2 cast source ID",
		},
		{
			name: "invalid round 2 cast target ID",
			round2Cast: &pb.FrostRound2Cast{
				Key: &pb.FrostMsgKey{
					SourceId: 1,
					TargetId: 1, // Invalid targetID since bcast targetID should always be 0
				},
			},
			errorMsg: "invalid round 2 cast target ID",
		},
		{
			name: "invalid round 2 cast validator index",
			round2Cast: &pb.FrostRound2Cast{
				Key: &pb.FrostMsgKey{
					SourceId: 1,
					TargetId: 0,
					ValIdx:   numVals, // Invalid ValIdx since it should be less than numVals
				},
			},
			errorMsg: "invalid round 2 cast validator index",
		},
		{
			name:             "invalid cast round",
			invalidRoundCast: true,
			errorMsg:         "bug: unexpected invalid message ID",
		},
		{
			name:                 "invalid round 1 casts message",
			invalidRound1CastMsg: true,
			errorMsg:             "invalid round 1 casts message",
		},
		{
			name:                 "invalid round 2 casts message",
			invalidRound2CastMsg: true,
			errorMsg:             "invalid round 2 casts message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callbackFunc := bcastCallback(peerMap, &mu, round1CastsRecv, round2CastsRecv, dedupRound1Casts, dedupRound2Casts, threshold, numVals)

			var err error
			if tt.round1Cast != nil {
				msg := pb.FrostRound1Casts{Casts: []*pb.FrostRound1Cast{tt.round1Cast}}
				err = callbackFunc(ctx, peers[0], round1CastID, &msg)
			}

			if tt.round2Cast != nil {
				msg := pb.FrostRound2Casts{Casts: []*pb.FrostRound2Cast{tt.round2Cast}}
				err = callbackFunc(ctx, peers[0], round2CastID, &msg)
			}

			if tt.invalidRoundCast {
				err = callbackFunc(ctx, peers[0], "invalid/round/id", nil)
			}
			if tt.invalidRound1CastMsg {
				err = callbackFunc(ctx, peers[0], round1CastID, nil) // nil round 1 message
			}
			if tt.invalidRound2CastMsg {
				err = callbackFunc(ctx, peers[0], round2CastID, nil) // nil round 2 message
			}

			require.Equal(t, err.Error(), tt.errorMsg)
		})

		dedupRound1Casts = make(map[peer.ID]bool) // Reset dedup map
		dedupRound2Casts = make(map[peer.ID]bool) // Reset dedup map
	}
}

func TestP2PCallback(t *testing.T) {
	const (
		n       = 4
		numVals = 2
	)

	var (
		ctx      = context.Background()
		peers    []peer.ID
		tcpNodes []host.Host
	)

	// Create libp2p peers
	peerMap := make(map[peer.ID]cluster.NodeIdx)
	for i := 0; i < n; i++ {
		secret, err := k1.GeneratePrivateKey()
		require.NoError(t, err)

		tcpNode := testutil.CreateHostWithIdentity(t, testutil.AvailableAddr(t), secret)
		peers = append(peers, tcpNode.ID())
		tcpNodes = append(tcpNodes, tcpNode)
		peerMap[tcpNode.ID()] = cluster.NodeIdx{
			PeerIdx:  i,
			ShareIdx: i + 1,
		}
	}

	var (
		round1P2PRecv = make(chan *pb.FrostRound1P2P, len(peers))

		mu             sync.Mutex
		dedupRound1P2P = make(map[peer.ID]bool)
	)

	tests := []struct {
		name                string
		key                 *pb.FrostMsgKey
		errorMsg            string
		invalidRound1P2PMsg bool
	}{
		{
			name: "invalid round 1 sourceID",
			key: &pb.FrostMsgKey{
				SourceId: 2,
			},
			errorMsg: "invalid round 1 p2p source ID",
		},
		{
			name: "invalid round 1 targetID",
			key: &pb.FrostMsgKey{
				SourceId: 1,
				TargetId: 2,
			},
			errorMsg: "invalid round 1 p2p target ID",
		},
		{
			name: "invalid round 1 validator index",
			key: &pb.FrostMsgKey{
				SourceId: 1,
				TargetId: 1,
				ValIdx:   numVals,
			},
			errorMsg: "invalid round 1 p2p validator index",
		},
		{
			name:                "invalid p2p message",
			invalidRound1P2PMsg: true,
			errorMsg:            "invalid round 1 p2p message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callbackFunc := p2pCallback(tcpNodes[0], peerMap, &mu, dedupRound1P2P, round1P2PRecv, numVals)

			if tt.invalidRound1P2PMsg {
				_, _, err := callbackFunc(ctx, peers[0], nil)
				require.Equal(t, err.Error(), tt.errorMsg)

				return
			}

			msg := pb.FrostRound1P2P{Shares: []*pb.FrostRound1ShamirShare{{Key: tt.key}}}

			resp, respBool, err := callbackFunc(ctx, peers[0], &msg)
			require.Equal(t, resp, nil)
			require.Equal(t, respBool, false)
			require.Equal(t, err.Error(), tt.errorMsg)
		})

		dedupRound1P2P = make(map[peer.ID]bool) // Reset dedup map
	}
}
