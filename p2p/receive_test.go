// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p_test

import (
	"context"
	"testing"

	"github.com/libp2p/go-libp2p/core/host"
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

func TestSendReceive(t *testing.T) {
	var (
		pID     = protocol.ID("delimited")
		ctx     = context.Background()
		servers = []host.Host{testutil.CreateHost(t, testutil.AvailableAddr(t)), testutil.CreateQUICHost(t, testutil.AvailableUDPAddr(t))}
		clients = []host.Host{testutil.CreateHost(t, testutil.AvailableAddr(t)), testutil.CreateQUICHost(t, testutil.AvailableUDPAddr(t))}
	)

	for i := range len(servers) {
		client, server := clients[i], servers[i]

		client.Peerstore().AddAddrs(server.ID(), server.Addrs(), peerstore.PermanentAddrTTL)

		// Register the server handler that either:
		//  - Errors if slot is negative
		//  - Echos the duty request if slot is even
		//  - Returns nothing is slot is odd
		p2p.RegisterHandler("server", server, pID,
			func() proto.Message { return new(pbv1.Duty) },
			func(ctx context.Context, peerID peer.ID, req proto.Message) (proto.Message, bool, error) {
				log.Info(ctx, "See protocol logging field")

				require.Equal(t, client.ID(), peerID)

				duty, ok := req.(*pbv1.Duty)
				require.True(t, ok)

				if duty.GetSlot()%2 == 0 {
					return duty, true, nil
				} else {
					return nil, false, nil
				}
			},
		)

		sendReceive := func(slot uint64) (*pbv1.Duty, error) {
			resp := new(pbv1.Duty)
			err := p2p.SendReceive(ctx, client, server.ID(), &pbv1.Duty{Slot: slot}, resp, pID)

			return resp, err
		}

		t.Run("ok", func(t *testing.T) {
			slot := uint64(100)
			resp, err := sendReceive(slot)
			require.NoError(t, err)
			require.Equal(t, slot, resp.GetSlot())
		})

		t.Run("empty response", func(t *testing.T) {
			_, err := sendReceive(101)
			require.ErrorContains(t, err, "read response: EOF")
		})
	}
}

// TestHandlerPanicRecovered verifies that a panic inside a stream handler (e.g. from a
// malformed peer message) is recovered so the process survives, and the node keeps serving
// subsequent requests. Without the recover, libp2p propagates the panic and crashes the process.
func TestHandlerPanicRecovered(t *testing.T) {
	var (
		pID    = protocol.ID("panicky")
		ctx    = context.Background()
		server = testutil.CreateHost(t, testutil.AvailableAddr(t))
		client = testutil.CreateHost(t, testutil.AvailableAddr(t))
	)

	client.Peerstore().AddAddrs(server.ID(), server.Addrs(), peerstore.PermanentAddrTTL)

	// Handler panics on odd slots and echoes on even slots.
	p2p.RegisterHandler("server", server, pID,
		func() proto.Message { return new(pbv1.Duty) },
		func(_ context.Context, _ peer.ID, req proto.Message) (proto.Message, bool, error) {
			duty, ok := req.(*pbv1.Duty)
			require.True(t, ok)

			if duty.GetSlot()%2 != 0 {
				panic("boom") // Simulates a handler panic reachable from a peer message.
			}

			return duty, true, nil
		},
	)

	sendReceive := func(slot uint64) error {
		return p2p.SendReceive(ctx, client, server.ID(), &pbv1.Duty{Slot: slot}, new(pbv1.Duty), pID)
	}

	// The panicking request fails at the stream level but must not crash the process.
	require.Error(t, sendReceive(1))

	// The node stays alive and keeps serving: a subsequent request succeeds.
	require.NoError(t, sendReceive(2))
}
