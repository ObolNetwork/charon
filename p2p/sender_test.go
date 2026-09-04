// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p_test

import (
	"context"
	"math"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestWithReceiveTimeout(t *testing.T) {
	servers := []host.Host{testutil.CreateHost(t, testutil.AvailableAddr(t)), testutil.CreateQUICHost(t, testutil.AvailableUDPAddr(t))}
	clients := []host.Host{testutil.CreateHost(t, testutil.AvailableAddr(t)), testutil.CreateQUICHost(t, testutil.AvailableUDPAddr(t))}

	// The zero receive timeout makes the server close the stream almost immediately,
	// racing the client's request write. TCP closes gracefully, so the write always
	// lands and the failure surfaces as an EOF on the response read. QUIC instead
	// resets the stream, which can abort the write already in flight, so accept either.
	expected := [][]string{
		{"read response: EOF"},
		{"read response: EOF", "stream reset"},
	}

	for i := range len(servers) {
		client, server, expect := clients[i], servers[i], expected[i]

		client.Peerstore().AddAddrs(server.ID(), server.Addrs(), time.Hour)

		protocolID := protocol.ID("testprotocol")
		p2p.RegisterHandler("test", server, protocolID, func() proto.Message { return new(pbv1.Duty) },
			func(ctx context.Context, peerID peer.ID, req proto.Message) (proto.Message, bool, error) {
				require.Error(t, ctx.Err()) // Assert the context has been closed already since 0 timeout.
				return nil, false, nil
			}, p2p.WithReceiveTimeout(0))

		err := p2p.SendReceive(context.Background(), client, server.ID(), new(pbv1.Duty), new(pbv1.Duty), protocolID)
		require.Error(t, err)
		require.True(t, slices.ContainsFunc(expect, func(s string) bool {
			return strings.Contains(err.Error(), s)
		}), "error %q contains none of %v", err, expect)
	}
}

func TestWithReadLimit(t *testing.T) {
	servers := []host.Host{testutil.CreateHost(t, testutil.AvailableAddr(t)), testutil.CreateQUICHost(t, testutil.AvailableUDPAddr(t))}
	clients := []host.Host{testutil.CreateHost(t, testutil.AvailableAddr(t)), testutil.CreateQUICHost(t, testutil.AvailableUDPAddr(t))}

	for i := range len(servers) {
		client, server := clients[i], servers[i]

		client.Peerstore().AddAddrs(server.ID(), server.Addrs(), time.Hour)

		protocolID := protocol.ID("testprotocol")

		var handled atomic.Bool

		p2p.RegisterHandler("test", server, protocolID, func() proto.Message { return new(pbv1.Duty) },
			func(context.Context, peer.ID, proto.Message) (proto.Message, bool, error) {
				handled.Store(true) // Must never run: the message exceeds the read limit.
				return nil, false, nil
			}, p2p.WithReadLimit(4)) // Tiny limit so any real message trips it.

		// Slot serializes to an 11 byte varint, well over the 4 byte read limit.
		err := p2p.SendReceive(context.Background(), client, server.ID(),
			&pbv1.Duty{Slot: math.MaxUint64}, new(pbv1.Duty), protocolID)
		require.Error(t, err)
		require.False(t, handled.Load(), "handler must not run when message exceeds read limit")
	}
}

func TestSendReceiveClosesStreamOnError(t *testing.T) {
	server := testutil.CreateHost(t, testutil.AvailableAddr(t))
	client := testutil.CreateHost(t, testutil.AvailableAddr(t))

	client.Peerstore().AddAddrs(server.ID(), server.Addrs(), peerstore.PermanentAddrTTL)

	protocolID := protocol.ID("testprotocol")

	p2p.RegisterHandler("test", server, protocolID,
		func() proto.Message { return new(pbv1.Duty) },
		func(context.Context, peer.ID, proto.Message) (proto.Message, bool, error) {
			time.Sleep(time.Second)
			return nil, false, nil
		})

	// Send multiple requests that will all time out on read.
	for range 5 {
		err := p2p.SendReceive(context.Background(), client, server.ID(),
			new(pbv1.Duty), new(pbv1.Duty), protocolID, p2p.WithSendTimeout(time.Millisecond))
		require.Error(t, err)
	}

	// Allow streams to fully close.
	time.Sleep(100 * time.Millisecond)

	var openStreams int
	for _, conn := range client.Network().ConnsToPeer(server.ID()) {
		openStreams += len(conn.GetStreams())
	}

	require.Zero(t, openStreams,
		"all streams must be closed after failed SendReceive calls")
}

func TestWithSendTimeout(t *testing.T) {
	servers := []host.Host{testutil.CreateHost(t, testutil.AvailableAddr(t)), testutil.CreateQUICHost(t, testutil.AvailableUDPAddr(t))}
	clients := []host.Host{testutil.CreateHost(t, testutil.AvailableAddr(t)), testutil.CreateQUICHost(t, testutil.AvailableUDPAddr(t))}
	errors := []string{"deadline reached", "deadline exceeded"}

	for i := range len(servers) {
		client, server, errorStr := clients[i], servers[i], errors[i]

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
		require.ErrorContains(t, err, errorStr)
	}
}

// errFields extracts the structured fields of an error into a map.
func errFields(t *testing.T, err error) map[string]any {
	t.Helper()

	fielder, ok := err.(interface{ Fields() []z.Field })
	require.True(t, ok, "error does not have structured fields")

	enc := zapcore.NewMapObjectEncoder()

	for _, field := range fielder.Fields() {
		field(func(zf zap.Field) {
			zf.AddTo(enc)
		})
	}

	return enc.Fields
}

func TestSendErrorContainsPeerField(t *testing.T) {
	ctx := context.Background()
	server := testutil.CreateHost(t, testutil.AvailableAddr(t))
	client := testutil.CreateHost(t, testutil.AvailableAddr(t))
	client.Peerstore().AddAddrs(server.ID(), server.Addrs(), peerstore.PermanentAddrTTL)

	peerName := p2p.PeerName(server.ID())

	t.Run("send new stream error", func(t *testing.T) {
		// No handler registered on the server, so protocol negotiation fails.
		err := p2p.Send(ctx, client, "unknown", server.ID(), &pbv1.Duty{Slot: 1})
		require.Error(t, err)
		require.Equal(t, peerName, errFields(t, err)["peer"])
	})

	t.Run("send receive new stream error", func(t *testing.T) {
		err := p2p.SendReceive(ctx, client, server.ID(), new(pbv1.Duty), new(pbv1.Duty), "unknown")
		require.Error(t, err)
		require.Equal(t, peerName, errFields(t, err)["peer"])
	})

	t.Run("send write error", func(t *testing.T) {
		protocolID := protocol.ID("testprotocol-peerfield")
		p2p.RegisterHandler("test", server, protocolID,
			func() proto.Message { return new(pbv1.Duty) },
			func(context.Context, peer.ID, proto.Message) (proto.Message, bool, error) {
				return nil, false, nil
			})

		// The negative send timeout sets an already-expired stream deadline, failing the write.
		err := p2p.Send(ctx, client, protocolID, server.ID(), &pbv1.Duty{Slot: 1},
			p2p.WithSendTimeout(-time.Second))
		require.Error(t, err)
		require.Equal(t, peerName, errFields(t, err)["peer"])
	})
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
		ctx     = context.Background()
		servers = []host.Host{testutil.CreateHost(t, testutil.AvailableAddr(t)), testutil.CreateQUICHost(t, testutil.AvailableUDPAddr(t))}
		clients = []host.Host{testutil.CreateHost(t, testutil.AvailableAddr(t)), testutil.CreateQUICHost(t, testutil.AvailableUDPAddr(t))}
	)

	var serverOpt []p2p.SendRecvOption
	if delimitedServer {
		serverOpt = append(serverOpt, p2p.WithDelimitedProtocol(delimitedID))
	}

	var clientOpt []p2p.SendRecvOption
	if delimitedClient {
		clientOpt = append(clientOpt, p2p.WithDelimitedProtocol(delimitedID))
	}

	for i := range len(servers) {
		client, server := clients[i], servers[i]

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
}
