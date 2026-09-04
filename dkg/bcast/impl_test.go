// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package bcast_test

import (
	"context"
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
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
	for range n {
		secret, err := k1.GeneratePrivateKey()
		require.NoError(t, err)

		secrets = append(secrets, secret)

		tcpNode := testutil.CreateHostWithIdentity(t, testutil.AvailableAddr(t), secret)
		tcpNodes = append(tcpNodes, tcpNode)

		peers = append(peers, tcpNode.ID())
	}

	// Connect peers
	for i := range n {
		for j := range n {
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
	for i := range n {
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

		bcastFunc := bcast.New(tcpNodes[i], peers, secrets[i], []byte("session hash"))

		bcastFunc.RegisterMessageIDFuncs(msgID1, callback, checkMessage)
		bcastFunc.RegisterMessageIDFuncs(msgID2, callback, checkMessage)

		bcasts = append(bcasts, bcastFunc.Broadcast)
	}

	assertResults := func(t *testing.T, expected result, source peer.ID) {
		t.Helper()

		targets := make(map[peer.ID]struct{})

		for range n - 1 {
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

// TestBCastRetriesTransientSendFailures ensures a reliable-broadcast survives transient
// p2p send failures in each phase instead of aborting the whole ceremony on the first one.
func TestBCastRetriesTransientSendFailures(t *testing.T) {
	const (
		n     = 3
		msgID = "msgID"
	)

	// The bcast protocol IDs are unexported; keep in sync with helpers.go.
	tests := []struct {
		name          string
		flakyProtocol protocol.ID
	}{
		{name: "signature request phase", flakyProtocol: "/charon/dkg/bcast/2.0.0/sig"},
		{name: "message send phase", flakyProtocol: "/charon/dkg/bcast/2.0.0/msg"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var (
				ctx      = context.Background()
				secrets  []*k1.PrivateKey
				tcpNodes []host.Host
				peers    []peer.ID
			)

			for range n {
				secret, err := k1.GeneratePrivateKey()
				require.NoError(t, err)

				secrets = append(secrets, secret)

				tcpNode := testutil.CreateHostWithIdentity(t, testutil.AvailableAddr(t), secret)
				tcpNodes = append(tcpNodes, tcpNode)

				peers = append(peers, tcpNode.ID())
			}

			for i := range n {
				for j := range n {
					tcpNodes[i].Peerstore().AddAddrs(tcpNodes[j].ID(), tcpNodes[j].Addrs(), peerstore.PermanentAddrTTL)
				}
			}

			// Node 0's first send to each peer in this phase fails transiently.
			tcpNodes[0] = testutil.NewFlakyHost(tcpNodes[0], n-1, test.flakyProtocol)

			received := make(chan proto.Message, n)
			callback := func(_ context.Context, _ peer.ID, _ string, msg proto.Message) error {
				received <- msg
				return nil
			}
			checkMessage := func(_ context.Context, _ peer.ID, msgAny *anypb.Any) error {
				var ts timestamppb.Timestamp
				if err := msgAny.UnmarshalTo(&ts); err != nil {
					return errors.Wrap(err, "anypb error")
				}

				return nil
			}

			var bcasts []bcast.BroadcastFunc

			for i := range n {
				bcastFunc := bcast.New(tcpNodes[i], peers, secrets[i], []byte("session hash"))
				bcastFunc.RegisterMessageIDFuncs(msgID, callback, checkMessage)
				bcasts = append(bcasts, bcastFunc.Broadcast)
			}

			msg := timestamppb.Now()
			err := bcasts[0](ctx, msgID, msg)
			require.NoError(t, err)

			for range n - 1 {
				require.True(t, proto.Equal(msg, <-received))
			}
		})
	}
}

// TestBCastSessionHashMismatch ensures that messages signed in one session
// cannot be verified in another, binding broadcasts to the cluster session.
func TestBCastSessionHashMismatch(t *testing.T) {
	const (
		n     = 2
		msgID = "msgID"
	)

	var (
		ctx      = context.Background()
		secrets  []*k1.PrivateKey
		tcpNodes []host.Host
		peers    []peer.ID
		bcasts   []bcast.BroadcastFunc
	)

	for range n {
		secret, err := k1.GeneratePrivateKey()
		require.NoError(t, err)

		secrets = append(secrets, secret)

		tcpNode := testutil.CreateHostWithIdentity(t, testutil.AvailableAddr(t), secret)
		tcpNodes = append(tcpNodes, tcpNode)

		peers = append(peers, tcpNode.ID())
	}

	for i := range n {
		for j := range n {
			tcpNodes[i].Peerstore().AddAddrs(tcpNodes[j].ID(), tcpNodes[j].Addrs(), peerstore.PermanentAddrTTL)
		}
	}

	callback := func(context.Context, peer.ID, string, proto.Message) error {
		return nil
	}
	checkMessage := func(_ context.Context, _ peer.ID, msgAny *anypb.Any) error {
		var ts timestamppb.Timestamp
		if err := msgAny.UnmarshalTo(&ts); err != nil {
			return errors.Wrap(err, "anypb error")
		}

		return nil
	}

	// Each peer runs with a different session hash.
	for i := range n {
		bcastFunc := bcast.New(tcpNodes[i], peers, secrets[i], []byte{byte(i)})
		bcastFunc.RegisterMessageIDFuncs(msgID, callback, checkMessage)
		bcasts = append(bcasts, bcastFunc.Broadcast)
	}

	// Signatures from a peer in a different session must not verify.
	err := bcasts[0](ctx, msgID, timestamppb.Now())
	require.ErrorContains(t, err, "verify signatures")
}
