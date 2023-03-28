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

func TestSendReceive(t *testing.T) {
	tests := []struct {
		name            string
		delimitedClient bool
		delimitedServer bool
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
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testSendReceive(t, test.delimitedClient, test.delimitedServer)
		})
	}
}

func testSendReceive(t *testing.T, delimitedClient, delimitedServer bool) {
	t.Helper()

	var (
		pID1        = protocol.ID("undelimited")
		pID2        = protocol.ID("delimited")
		errNegative = errors.New("negative slot")
		ctx         = context.Background()
		server      = testutil.CreateHost(t, testutil.AvailableAddr(t))
		client      = testutil.CreateHost(t, testutil.AvailableAddr(t))
	)

	var serverOpt []p2p.SendRecvOption
	if delimitedServer {
		serverOpt = append(serverOpt, p2p.WithDelimitedProtocol(pID2))
	}

	var clientOpt []p2p.SendRecvOption
	if delimitedClient {
		clientOpt = append(clientOpt, p2p.WithDelimitedProtocol(pID2))
	}

	client.Peerstore().AddAddrs(server.ID(), server.Addrs(), peerstore.PermanentAddrTTL)

	// Register the server handler that either:
	//  - Errors is slot is negative
	//  - Echos the duty request if slot is even
	//  - Returns nothing is slot is odd
	p2p.RegisterHandler("server", server, pID1,
		func() proto.Message { return new(pbv1.Duty) },
		func(ctx context.Context, peerID peer.ID, req proto.Message) (proto.Message, bool, error) {
			log.Info(ctx, "See protocol logging field")

			require.Equal(t, client.ID(), peerID)
			duty, ok := req.(*pbv1.Duty)
			require.True(t, ok)

			if duty.Slot < 0 {
				return nil, false, errNegative
			} else if duty.Slot%2 == 0 {
				return duty, true, nil
			} else {
				return nil, false, nil
			}
		},
		serverOpt...,
	)

	sendReceive := func(slot int64) (*pbv1.Duty, error) {
		resp := new(pbv1.Duty)
		err := p2p.SendReceive(ctx, client, server.ID(), &pbv1.Duty{Slot: slot}, resp, pID1, clientOpt...)

		return resp, err
	}

	t.Run("server error", func(t *testing.T) {
		_, err := sendReceive(-1)
		require.ErrorContains(t, err, "no response")
	})

	t.Run("ok", func(t *testing.T) {
		slot := int64(100)
		resp, err := sendReceive(slot)
		require.NoError(t, err)
		require.Equal(t, slot, resp.Slot)
	})

	t.Run("empty response", func(t *testing.T) {
		_, err := sendReceive(101)
		require.ErrorContains(t, err, "no response")
	})
}
