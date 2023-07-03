// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p_test

import (
	"context"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestSend(t *testing.T) {
	tests := []struct {
		name                string
		delimitedClient     bool
		delimitedServer     bool
		delimitedOnlyClient bool
		delimitedOnlyServer bool
	}{
		{
			name:            "non-delimited client and server",
			delimitedClient: false,
			delimitedServer: false,
		},
		{
			name:            "delimited client and server",
			delimitedClient: true,
			delimitedServer: true,
		},
		{
			name:            "delimited client and non-delimited server",
			delimitedClient: true,
			delimitedServer: false,
		},
		{
			name:            "non-delimited client and delimited server",
			delimitedClient: false,
			delimitedServer: true,
		},
		{
			name:                "delimited only client and delimited server",
			delimitedClient:     true,
			delimitedServer:     true,
			delimitedOnlyClient: true,
		},
		{
			name:                "delimited client and delimited only server",
			delimitedClient:     true,
			delimitedServer:     true,
			delimitedOnlyServer: true,
		},
		{
			name:                "delimited only client and delimited only server",
			delimitedClient:     true,
			delimitedServer:     true,
			delimitedOnlyServer: true,
			delimitedOnlyClient: true,
		},
		{
			name:                "delimited only client and non-delimited server, protocols not supported",
			delimitedClient:     true,
			delimitedServer:     false,
			delimitedOnlyClient: true,
		},
		{
			name:                "non-delimited client and delimited only server, protocols not supported",
			delimitedClient:     false,
			delimitedServer:     true,
			delimitedOnlyServer: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testSend(t, test.delimitedClient, test.delimitedServer, test.delimitedOnlyClient, test.delimitedOnlyServer)
		})
	}
}

func testSend(t *testing.T, delimitedClient, delimitedServer, delimitedOnlyClient, delimitedOnlyServer bool) {
	t.Helper()

	var (
		pID1        = protocol.ID("undelimited")
		pID2        = protocol.ID("delimited")
		errNegative = errors.New("negative slot")
		ctx         = context.Background()
		server      = testutil.CreateHost(t, testutil.AvailableAddr(t))
		client      = testutil.CreateHost(t, testutil.AvailableAddr(t))
	)

	getBasicProtoIDClient := func() protocol.ID {
		if delimitedClient && delimitedOnlyClient {
			return pID2
		}

		return pID1
	}

	getBasicProtoIDServer := func() protocol.ID {
		if delimitedServer && delimitedOnlyServer {
			return pID2
		}

		return pID1
	}

	var serverOpt []p2p.SendRecvOption
	if delimitedServer {
		serverOpt = append(serverOpt, p2p.WithDelimitedProtocol(pID2))
	}

	var clientOpt []p2p.SendRecvOption
	if delimitedClient {
		clientOpt = append(clientOpt, p2p.WithDelimitedProtocol(pID2))
	}

	client.Peerstore().AddAddrs(server.ID(), server.Addrs(), peerstore.PermanentAddrTTL)

	// Catch server errors.
	serverErrChan := make(chan error)

	// Register the server handler that either:
	//  - Errors if slot is negative
	//  - Returns nothing otherwise
	p2p.RegisterHandler("server", server, getBasicProtoIDServer(),
		func() proto.Message { return new(pbv1.Duty) },
		func(ctx context.Context, peerID peer.ID, req proto.Message) (proto.Message, bool, error) {
			log.Info(ctx, "See protocol logging field")

			require.Equal(t, client.ID(), peerID)
			duty, ok := req.(*pbv1.Duty)
			require.True(t, ok)

			var err error
			defer func() {
				serverErrChan <- err
			}()

			if duty.Slot < 0 {
				err = errNegative
			}

			return nil, false, err
		},
		serverOpt...,
	)

	protocolNotSupported := func() bool {
		// Client supports ONLY delimited protocol while Server supports ONLY non-delimited protocol.
		if getBasicProtoIDClient() == pID2 && !delimitedServer {
			return true
		}

		// Server supports ONLY delimited protocol while Client supports ONLY non-delimited protocol.
		if getBasicProtoIDServer() == pID2 && !delimitedClient {
			return true
		}

		return false
	}

	if protocolNotSupported() {
		err := p2p.Send(ctx, client, getBasicProtoIDClient(), server.ID(), &pbv1.Duty{Slot: 100}, clientOpt...)
		require.ErrorContains(t, err, "protocols not supported")

		return
	}

	t.Run("server error", func(t *testing.T) {
		err := p2p.Send(ctx, client, getBasicProtoIDClient(), server.ID(), &pbv1.Duty{Slot: -1}, clientOpt...)
		require.NoError(t, err)
		require.ErrorContains(t, <-serverErrChan, "negative slot")
	})

	t.Run("ok", func(t *testing.T) {
		err := p2p.Send(ctx, client, getBasicProtoIDClient(), server.ID(), &pbv1.Duty{Slot: 100}, clientOpt...)
		require.NoError(t, err)
		require.NoError(t, <-serverErrChan)
	})
}
