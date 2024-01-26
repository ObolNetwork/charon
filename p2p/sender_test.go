// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p_test

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/log"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestWithReceiveTimeout(t *testing.T) {
	server := testutil.CreateHost(t, testutil.AvailableAddr(t))
	client := testutil.CreateHost(t, testutil.AvailableAddr(t))

	client.Peerstore().AddAddrs(server.ID(), server.Addrs(), time.Hour)

	protocolID := protocol.ID("testprotocol")
	p2p.RegisterHandler("test", server, protocolID, func() proto.Message { return new(pbv1.Duty) },
		func(ctx context.Context, peerID peer.ID, req proto.Message) (proto.Message, bool, error) {
			require.Error(t, ctx.Err()) // Assert the context has been closed already since 0 timeout.
			return nil, false, nil
		}, p2p.WithReceiveTimeout(0))

	err := p2p.SendReceive(context.Background(), client, server.ID(), new(pbv1.Duty), new(pbv1.Duty), protocolID)
	require.Error(t, err)
	require.ErrorContains(t, err, "read response: EOF")
}

func TestWithSendTimeout(t *testing.T) {
	server := testutil.CreateHost(t, testutil.AvailableAddr(t))
	client := testutil.CreateHost(t, testutil.AvailableAddr(t))

	client.Peerstore().AddAddrs(server.ID(), server.Addrs(), time.Hour)

	protocolID := protocol.ID("testprotocol")
	sendTimeout := time.Millisecond
	p2p.RegisterHandler("test", server, protocolID, func() proto.Message { return new(pbv1.Duty) },
		func(ctx context.Context, peerID peer.ID, req proto.Message) (proto.Message, bool, error) {
			// The delay must be much greater than the send timeout to trigger the deadline error.
			time.Sleep(10 * sendTimeout)
			return nil, false, nil
		})

	err := p2p.SendReceive(context.Background(), client, server.ID(),
		new(pbv1.Duty), new(pbv1.Duty), protocolID, p2p.WithSendTimeout(sendTimeout))
	require.Error(t, err)
	require.ErrorContains(t, err, "deadline reached")
}

func TestSend(t *testing.T) {
	var (
		undelimID = protocol.ID("undelimited")
		delimID   = protocol.ID("delimited")
	)

	tests := []struct {
		name               string
		delimitedClient    bool
		delimitedServer    bool
		clientBasicProtoID protocol.ID
		serverBasicProtoID protocol.ID
	}{
		{
			name:               "non-delimited client and server",
			delimitedClient:    false,
			delimitedServer:    false,
			clientBasicProtoID: undelimID,
			serverBasicProtoID: undelimID,
		},
		{
			name:               "delimited client and server",
			delimitedClient:    true,
			delimitedServer:    true,
			clientBasicProtoID: undelimID,
			serverBasicProtoID: undelimID,
		},
		{
			name:               "delimited client and non-delimited server",
			delimitedClient:    true,
			delimitedServer:    false,
			clientBasicProtoID: undelimID,
			serverBasicProtoID: undelimID,
		},
		{
			name:               "non-delimited client and delimited server",
			delimitedClient:    false,
			delimitedServer:    true,
			clientBasicProtoID: undelimID,
			serverBasicProtoID: undelimID,
		},
		{
			name:               "delimited only client and delimited server",
			delimitedClient:    true,
			delimitedServer:    true,
			clientBasicProtoID: delimID,
			serverBasicProtoID: undelimID,
		},
		{
			name:               "delimited client and delimited only server",
			delimitedClient:    true,
			delimitedServer:    true,
			clientBasicProtoID: undelimID,
			serverBasicProtoID: delimID,
		},
		{
			name:               "delimited only client and delimited only server",
			delimitedClient:    true,
			delimitedServer:    true,
			clientBasicProtoID: delimID,
			serverBasicProtoID: delimID,
		},
		{
			name:               "delimited only client and non-delimited server, protocols not supported",
			delimitedClient:    true,
			delimitedServer:    false,
			clientBasicProtoID: delimID,
			serverBasicProtoID: undelimID,
		},
		{
			name:               "non-delimited client and delimited only server, protocols not supported",
			delimitedClient:    false,
			delimitedServer:    true,
			clientBasicProtoID: undelimID,
			serverBasicProtoID: delimID,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testSend(t, test.clientBasicProtoID, test.serverBasicProtoID, delimID, test.delimitedClient, test.delimitedServer)
		})
	}
}

func testSend(t *testing.T, clientBasicProtoID, serverBasicProtoID, delimitedID protocol.ID, delimitedClient, delimitedServer bool) {
	t.Helper()

	var (
		ctx    = context.Background()
		server = testutil.CreateHost(t, testutil.AvailableAddr(t))
		client = testutil.CreateHost(t, testutil.AvailableAddr(t))
	)

	var serverOpt []p2p.SendRecvOption
	if delimitedServer {
		serverOpt = append(serverOpt, p2p.WithDelimitedProtocol(delimitedID))
	}

	var clientOpt []p2p.SendRecvOption
	if delimitedClient {
		clientOpt = append(clientOpt, p2p.WithDelimitedProtocol(delimitedID))
	}

	client.Peerstore().AddAddrs(server.ID(), server.Addrs(), peerstore.PermanentAddrTTL)

	// Catch server errors.
	serverErrChan := make(chan error)

	// Register the server handler that either:
	//  - Errors if slot is negative
	//  - Returns nothing otherwise
	p2p.RegisterHandler("server", server, serverBasicProtoID,
		func() proto.Message { return new(pbv1.Duty) },
		func(ctx context.Context, peerID peer.ID, req proto.Message) (proto.Message, bool, error) {
			log.Info(ctx, "See protocol logging field")

			require.Equal(t, client.ID(), peerID)

			var err error
			defer func() {
				serverErrChan <- err
			}()

			return nil, false, err
		},
		serverOpt...,
	)

	protocolNotSupported := func() bool {
		// Client supports ONLY delimited protocol while Server supports ONLY non-delimited protocol.
		if clientBasicProtoID == delimitedID && !delimitedServer {
			return true
		}

		// Server supports ONLY delimited protocol while Client supports ONLY non-delimited protocol.
		if serverBasicProtoID == delimitedID && !delimitedClient {
			return true
		}

		return false
	}

	if protocolNotSupported() {
		err := p2p.Send(ctx, client, clientBasicProtoID, server.ID(), &pbv1.Duty{Slot: 100}, clientOpt...)
		require.ErrorContains(t, err, "protocols not supported")

		return
	}

	t.Run("ok", func(t *testing.T) {
		err := p2p.Send(ctx, client, clientBasicProtoID, server.ID(), &pbv1.Duty{Slot: 100}, clientOpt...)
		require.NoError(t, err)
		require.NoError(t, <-serverErrChan)
	})
}
