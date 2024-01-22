// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package bcast_test

import (
	"context"
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/dkg/bcast"
	"github.com/obolnetwork/charon/testutil"
)

func TestBCast(t *testing.T) {
	const n = 3

	var (
		ctx          = context.Background()
		msgID1       = "msgID1"
		msgID2       = "msgID2"
		msgIDInvalid = "msgIDInvalid"

		secrets  []*k1.PrivateKey
		tcpNodes []host.Host
		peers    []peer.ID
		bcasts   []bcast.BroadcastFunc
	)

	// Create secretes and libp2p nodes
	for i := 0; i < n; i++ {
		secret, err := k1.GeneratePrivateKey()
		require.NoError(t, err)
		secrets = append(secrets, secret)

		tcpNode := testutil.CreateHostWithIdentity(t, testutil.AvailableAddr(t), secret)
		tcpNodes = append(tcpNodes, tcpNode)

		peers = append(peers, tcpNode.ID())
	}

	// Connect peers
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			tcpNodes[i].Peerstore().AddAddrs(tcpNodes[j].ID(), tcpNodes[j].Addrs(), peerstore.PermanentAddrTTL)
		}
	}

	// Collect results

	type result struct {
		Source peer.ID
		Target peer.ID
		MsgID  string
		Msg    proto.Message
	}
	results := make(chan result, 1024)

	// Create broadcasters
	for i := 0; i < n; i++ {
		i := i
		callback := func(_ context.Context, peerID peer.ID, msgID string, msg proto.Message) error {
			results <- result{Source: peerID, MsgID: msgID, Msg: msg, Target: peers[i]}
			return nil
		}

		checkMessage := func(_ context.Context, _ peer.ID, msgAny *anypb.Any) error {
			var ts timestamppb.Timestamp
			err := msgAny.UnmarshalTo(&ts)
			if err != nil {
				return errors.Wrap(err, "anypb error")
			}

			return nil
		}

		bcastFunc := bcast.New(tcpNodes[i], peers, secrets[i])

		bcastFunc.RegisterMessageIDFuncs(msgID1, callback, checkMessage)
		bcastFunc.RegisterMessageIDFuncs(msgID2, callback, checkMessage)

		bcasts = append(bcasts, bcastFunc.Broadcast)
	}

	assertResults := func(t *testing.T, expected result, source peer.ID) {
		t.Helper()

		targets := make(map[peer.ID]struct{})
		for i := 0; i < n-1; i++ {
			actual := <-results
			require.Equal(t, expected.Source, actual.Source)
			require.Equal(t, expected.MsgID, actual.MsgID)
			require.True(t, proto.Equal(expected.Msg, actual.Msg))
			targets[actual.Target] = struct{}{}
		}

		// Check that all peers received the message
		for _, peerID := range peers {
			if peerID == source {
				continue
			}
			_, ok := targets[peerID]
			require.True(t, ok)
		}
	}

	// Broadcast from peer 0, should succeed.
	p0Result := result{
		Msg:    timestamppb.Now(),
		MsgID:  msgID1,
		Source: peers[0],
	}
	err := bcasts[0](ctx, p0Result.MsgID, p0Result.Msg)
	require.NoError(t, err)
	assertResults(t, p0Result, peers[0])

	// Broadcast from peer 1, should succeed.
	p1Result := result{
		Msg:    timestamppb.Now(),
		MsgID:  msgID2,
		Source: peers[1],
	}
	err = bcasts[1](ctx, p1Result.MsgID, p1Result.Msg)
	require.NoError(t, err)
	assertResults(t, p1Result, peers[1])

	// Broadcast different message for same ID from peer 0, should error.
	err = bcasts[0](ctx, msgID1, timestamppb.Now())
	require.Error(t, err)

	// Broadcast invalid message ID from peer 0, should error.
	err = bcasts[0](ctx, msgIDInvalid, timestamppb.Now())
	require.Error(t, err)

	// Broadcast duplicate message from peer 0, should succeed.
	err = bcasts[0](ctx, p0Result.MsgID, p0Result.Msg)
	require.NoError(t, err)
	assertResults(t, p0Result, peers[0])
}
