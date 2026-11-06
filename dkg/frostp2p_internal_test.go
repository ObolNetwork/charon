// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"
	"testing"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg/bcast"
	pb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/testutil"
)

// TestFrostRound1RetriesTransientSendFailures ensures the frost round-1 p2p transport
// survives transient send failures instead of aborting the whole ceremony on the first one.
func TestFrostRound1RetriesTransientSendFailures(t *testing.T) {
	const (
		nodes     = 3
		threshold = 2
		numVals   = 2
		dkgCtx    = "test round 1 retries"
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var (
		secrets []*k1.PrivateKey
		hosts   []host.Host
		peers   []peer.ID
		peerMap = make(map[peer.ID]cluster.NodeIdx)
	)

	for i := range nodes {
		secret, err := k1.GeneratePrivateKey()
		require.NoError(t, err)

		secrets = append(secrets, secret)

		h := testutil.CreateHostWithIdentity(t, testutil.AvailableAddr(t), secret)
		hosts = append(hosts, h)
		peers = append(peers, h.ID())
		peerMap[h.ID()] = cluster.NodeIdx{PeerIdx: i, ShareIdx: i + 1}
	}

	for i := range nodes {
		for j := range nodes {
			if i == j {
				continue
			}

			hosts[i].Peerstore().AddAddrs(peers[j], hosts[j].Addrs(), peerstore.PermanentAddrTTL)
		}
	}

	// Node 0's first round-1 p2p send to each peer fails transiently,
	// leaving the reliable-broadcast phase untouched.
	hosts[0] = testutil.NewFlakyHost(hosts[0], nodes-1, round1P2PID)

	var transports []*frostP2P

	for i := range nodes {
		bcastComp := bcast.New(hosts[i], peers, secrets[i], []byte("session hash"))

		tp, err := newFrostP2P(hosts[i], peerMap, bcastComp, threshold, numVals)
		require.NoError(t, err)

		transports = append(transports, tp)
	}

	errChan := make(chan error, nodes)

	for i := range nodes {
		go func(node int) {
			validators, err := newFrostParticipants(numVals, nodes, threshold, uint32(node+1), dkgCtx)
			if err != nil {
				errChan <- err
				return
			}

			castR1, p2pR1, err := round1(validators)
			if err != nil {
				errChan <- err
				return
			}

			_, _, err = transports[node].Round1(ctx, castR1, p2pR1)
			errChan <- err
		}(i)
	}

	for range nodes {
		require.NoError(t, <-errChan)
	}
}

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

	for i := range n {
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
			callbackFunc := newBcastCallback(peerMap, round1CastsRecv, round2CastsRecv, threshold, numVals)

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

	for i := range n {
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
			round1P2PRecv := make(chan *pb.FrostRound1P2P, len(peers))

			callbackFunc := newP2PCallback(tcpNodes[0], peerMap, round1P2PRecv, numVals)

			if tt.invalidRound1P2PMsg {
				_, _, err := callbackFunc(ctx, peers[0], nil)
				require.Equal(t, err.Error(), tt.errorMsg)

				return
			}

			msg := pb.FrostRound1P2P{Shares: []*pb.FrostRound1ShamirShare{{Key: tt.key}}}

			resp, respBool, err := callbackFunc(ctx, peers[0], &msg)
			require.Nil(t, resp)
			require.False(t, respBool)
			require.Equal(t, err.Error(), tt.errorMsg)
		})
	}
}
