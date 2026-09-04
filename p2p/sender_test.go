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
	"github.com/libp2p/go-libp2p/core/network"
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

	for i := range len(servers) {
		client, server := clients[i], servers[i]

		client.Peerstore().AddAddrs(server.ID(), server.Addrs(), time.Hour)

		protocolID := protocol.ID("testprotocol")
		sendTimeout := time.Millisecond

		p2p.RegisterHandler("test", server, protocolID, func() proto.Message { return new(pbv1.Duty) },
			func(ctx context.Context, peerID peer.ID, req proto.Message) (proto.Message, bool, error) {
				// The delay must be much greater than the send timeout to trigger the deadline error.
				time.Sleep(10 * sendTimeout)
				return nil, false, nil
			})

		// Depending on how far the tiny budget lets the call get, the deadline error
		// surfaces at dialing ("context deadline exceeded"), or on the stream
		// ("deadline reached" on TCP, "deadline exceeded" on QUIC).
		err := p2p.SendReceive(context.Background(), client, server.ID(),
			new(pbv1.Duty), new(pbv1.Duty), protocolID, p2p.WithSendTimeout(sendTimeout))
		require.Error(t, err)
		require.ErrorContains(t, err, "deadline")
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

func TestSendRetries(t *testing.T) {
	ctx := context.Background()
	server := testutil.CreateHost(t, testutil.AvailableAddr(t))
	client := testutil.CreateHost(t, testutil.AvailableAddr(t))
	client.Peerstore().AddAddrs(server.ID(), server.Addrs(), peerstore.PermanentAddrTTL)

	received := make(chan *pbv1.Duty, 1)
	protocolID := protocol.ID("testprotocol-retries")
	p2p.RegisterHandler("test", server, protocolID,
		func() proto.Message { return new(pbv1.Duty) },
		func(_ context.Context, _ peer.ID, req proto.Message) (proto.Message, bool, error) {
			duty, ok := req.(*pbv1.Duty)
			require.True(t, ok)

			received <- duty

			return nil, false, nil
		})

	t.Run("no retries by default", func(t *testing.T) {
		flaky := testutil.NewFlakyHost(client, 1)
		err := p2p.Send(ctx, flaky, protocolID, server.ID(), &pbv1.Duty{Slot: 1})
		require.Error(t, err)
		require.Equal(t, 1, flaky.Calls())
	})

	t.Run("retries transient failures", func(t *testing.T) {
		flaky := testutil.NewFlakyHost(client, 2)
		err := p2p.Send(ctx, flaky, protocolID, server.ID(), &pbv1.Duty{Slot: 2}, p2p.WithRetries(2))
		require.NoError(t, err)
		require.Equal(t, 3, flaky.Calls())

		select {
		case duty := <-received:
			require.EqualValues(t, 2, duty.GetSlot())
		case <-time.After(5 * time.Second):
			require.Fail(t, "timed out waiting for message")
		}
	})

	t.Run("fails when retries exhausted", func(t *testing.T) {
		flaky := testutil.NewFlakyHost(client, 3)
		err := p2p.Send(ctx, flaky, protocolID, server.ID(), &pbv1.Duty{Slot: 3}, p2p.WithRetries(2))
		require.ErrorContains(t, err, "transient stream failure")
		require.Equal(t, 3, flaky.Calls())
	})

	t.Run("retries bounded by send timeout", func(t *testing.T) {
		flaky := testutil.NewFlakyHost(client, 100)
		t0 := time.Now()

		// The send timeout is the total budget for all attempts, so the retry
		// sequence must stop long before all 8 retries (~7s of backoff) elapse.
		err := p2p.Send(ctx, flaky, protocolID, server.ID(), &pbv1.Duty{Slot: 5},
			p2p.WithRetries(8), p2p.WithSendTimeout(200*time.Millisecond))
		require.ErrorContains(t, err, "transient stream failure")
		require.Less(t, time.Since(t0), 3*time.Second)
		require.Less(t, flaky.Calls(), 9)
	})

	t.Run("cancellation surfaces as context error", func(t *testing.T) {
		cancelledCtx, cancel := context.WithCancel(ctx)
		cancel()

		flaky := testutil.NewFlakyHost(client, 10)
		err := p2p.Send(cancelledCtx, flaky, protocolID, server.ID(), &pbv1.Duty{Slot: 4}, p2p.WithRetries(5))
		require.ErrorIs(t, err, context.Canceled)
		require.Equal(t, 1, flaky.Calls())
	})
}

// blockingHost wraps a host whose NewStream blocks until the context is done,
// simulating a hung dial or protocol negotiation.
type blockingHost struct {
	host.Host
}

func (h blockingHost) NewStream(ctx context.Context, _ peer.ID, _ ...protocol.ID) (network.Stream, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestSendTimeoutBoundsStreamCreation(t *testing.T) {
	ctx := context.Background()
	server := testutil.CreateHost(t, testutil.AvailableAddr(t))
	client := testutil.CreateHost(t, testutil.AvailableAddr(t))
	client.Peerstore().AddAddrs(server.ID(), server.Addrs(), peerstore.PermanentAddrTTL)

	blocking := blockingHost{Host: client}

	tests := []struct {
		name string
		send func() error
	}{
		{
			name: "send",
			send: func() error {
				return p2p.Send(ctx, blocking, "proto", server.ID(), &pbv1.Duty{Slot: 1},
					p2p.WithSendTimeout(100*time.Millisecond), p2p.WithRetries(2))
			},
		},
		{
			name: "send receive",
			send: func() error {
				return p2p.SendReceive(ctx, blocking, server.ID(), new(pbv1.Duty), new(pbv1.Duty), "proto",
					p2p.WithSendTimeout(100*time.Millisecond), p2p.WithRetries(2))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			errChan := make(chan error, 1)
			go func() {
				errChan <- test.send()
			}()

			select {
			case err := <-errChan:
				require.ErrorIs(t, err, context.DeadlineExceeded)
			case <-time.After(2 * time.Second):
				require.Fail(t, "send blocked past its timeout budget on stream creation")
			}
		})
	}
}

// blockOnceHost wraps a host whose first NewStream blocks until the context is done,
// simulating a hung dial on the first attempt only.
type blockOnceHost struct {
	host.Host

	calls atomic.Int32
}

func (h *blockOnceHost) NewStream(ctx context.Context, peerID peer.ID, pIDs ...protocol.ID) (network.Stream, error) {
	if h.calls.Add(1) == 1 {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	return h.Host.NewStream(ctx, peerID, pIDs...)
}

// TestSendRetriesAfterStalledDial ensures a hung dial only consumes its slice of the
// total send budget, leaving room for a retry.
func TestSendRetriesAfterStalledDial(t *testing.T) {
	ctx := context.Background()
	server := testutil.CreateHost(t, testutil.AvailableAddr(t))
	client := testutil.CreateHost(t, testutil.AvailableAddr(t))
	client.Peerstore().AddAddrs(server.ID(), server.Addrs(), peerstore.PermanentAddrTTL)

	received := make(chan *pbv1.Duty, 1)
	protocolID := protocol.ID("testprotocol-stalled-dial")
	p2p.RegisterHandler("test", server, protocolID,
		func() proto.Message { return new(pbv1.Duty) },
		func(_ context.Context, _ peer.ID, req proto.Message) (proto.Message, bool, error) {
			duty, ok := req.(*pbv1.Duty)
			require.True(t, ok)

			received <- duty

			return nil, false, nil
		})

	blocking := &blockOnceHost{Host: client}
	err := p2p.Send(ctx, blocking, protocolID, server.ID(), &pbv1.Duty{Slot: 7},
		p2p.WithSendTimeout(2*time.Second), p2p.WithRetries(2))
	require.NoError(t, err)
	require.GreaterOrEqual(t, blocking.calls.Load(), int32(2))

	select {
	case duty := <-received:
		require.EqualValues(t, 7, duty.GetSlot())
	case <-time.After(5 * time.Second):
		require.Fail(t, "timed out waiting for message")
	}
}

// TestSendReceiveAllowsSlowResponse ensures each SendReceive attempt gets the full send
// timeout for the response wait, not a slice of it, so a peer that legitimately responds
// slower than sendTimeout/(retries+1) is not aborted.
func TestSendReceiveAllowsSlowResponse(t *testing.T) {
	ctx := context.Background()
	server := testutil.CreateHost(t, testutil.AvailableAddr(t))
	client := testutil.CreateHost(t, testutil.AvailableAddr(t))
	client.Peerstore().AddAddrs(server.ID(), server.Addrs(), peerstore.PermanentAddrTTL)

	var calls atomic.Int32

	protocolID := protocol.ID("testprotocol-slow-response")
	p2p.RegisterHandler("test", server, protocolID,
		func() proto.Message { return new(pbv1.Duty) },
		func(_ context.Context, _ peer.ID, req proto.Message) (proto.Message, bool, error) {
			calls.Add(1)
			// Respond slower than a sliced budget (1s/6 ≈ 166ms) would allow, but
			// well within the full 1s send timeout.
			time.Sleep(400 * time.Millisecond)

			duty, ok := req.(*pbv1.Duty)
			require.True(t, ok)

			return &pbv1.Duty{Slot: duty.GetSlot() + 1}, true, nil
		})

	resp := new(pbv1.Duty)
	err := p2p.SendReceive(ctx, client, server.ID(), &pbv1.Duty{Slot: 41}, resp, protocolID,
		p2p.WithSendTimeout(time.Second), p2p.WithRetries(5))
	require.NoError(t, err)
	require.EqualValues(t, 42, resp.GetSlot())
	require.EqualValues(t, 1, calls.Load(), "slow but valid response must succeed on the first attempt")
}

func TestWithRetriesClampsNegative(t *testing.T) {
	ctx := context.Background()
	server := testutil.CreateHost(t, testutil.AvailableAddr(t))
	client := testutil.CreateHost(t, testutil.AvailableAddr(t))
	client.Peerstore().AddAddrs(server.ID(), server.Addrs(), peerstore.PermanentAddrTTL)

	protocolID := protocol.ID("testprotocol-negative-retries")
	p2p.RegisterHandler("test", server, protocolID,
		func() proto.Message { return new(pbv1.Duty) },
		func(context.Context, peer.ID, proto.Message) (proto.Message, bool, error) {
			return nil, false, nil
		})

	// A negative retry count must not panic (it would divide by zero when computing the
	// per-attempt slice) and behaves as zero retries.
	require.NotPanics(t, func() {
		flaky := testutil.NewFlakyHost(client, 1)
		err := p2p.Send(ctx, flaky, protocolID, server.ID(), &pbv1.Duty{Slot: 1}, p2p.WithRetries(-1))
		require.Error(t, err)
		require.Equal(t, 1, flaky.Calls())
	})
}

// TestSendReceiveRetriesAfterStall ensures a stalled attempt only consumes its slice of
// the total send budget, leaving room for a retry on a fresh stream — the incident mode
// where a stream stalls until its I/O deadline.
func TestSendReceiveRetriesAfterStall(t *testing.T) {
	ctx := context.Background()
	server := testutil.CreateHost(t, testutil.AvailableAddr(t))
	client := testutil.CreateHost(t, testutil.AvailableAddr(t))
	client.Peerstore().AddAddrs(server.ID(), server.Addrs(), peerstore.PermanentAddrTTL)

	var calls atomic.Int32

	protocolID := protocol.ID("testprotocol-stall-retries")
	p2p.RegisterHandler("test", server, protocolID,
		func() proto.Message { return new(pbv1.Duty) },
		func(_ context.Context, _ peer.ID, req proto.Message) (proto.Message, bool, error) {
			if calls.Add(1) == 1 {
				time.Sleep(3 * time.Second) // Stall the first attempt past its deadline.
			}

			duty, ok := req.(*pbv1.Duty)
			require.True(t, ok)

			return &pbv1.Duty{Slot: duty.GetSlot() + 1}, true, nil
		})

	resp := new(pbv1.Duty)
	err := p2p.SendReceive(ctx, client, server.ID(), &pbv1.Duty{Slot: 41}, resp, protocolID,
		p2p.WithSendTimeout(2*time.Second), p2p.WithRetries(2))
	require.NoError(t, err)
	require.EqualValues(t, 42, resp.GetSlot())
	require.GreaterOrEqual(t, calls.Load(), int32(2))
}

func TestSendReceiveRetries(t *testing.T) {
	ctx := context.Background()
	server := testutil.CreateHost(t, testutil.AvailableAddr(t))
	client := testutil.CreateHost(t, testutil.AvailableAddr(t))
	client.Peerstore().AddAddrs(server.ID(), server.Addrs(), peerstore.PermanentAddrTTL)

	protocolID := protocol.ID("testprotocol-sendrecv-retries")
	p2p.RegisterHandler("test", server, protocolID,
		func() proto.Message { return new(pbv1.Duty) },
		func(_ context.Context, _ peer.ID, req proto.Message) (proto.Message, bool, error) {
			duty, ok := req.(*pbv1.Duty)
			require.True(t, ok)

			return &pbv1.Duty{Slot: duty.GetSlot() + 1}, true, nil
		})

	flaky := testutil.NewFlakyHost(client, 2)
	resp := new(pbv1.Duty)
	err := p2p.SendReceive(ctx, flaky, server.ID(), &pbv1.Duty{Slot: 41}, resp, protocolID, p2p.WithRetries(2))
	require.NoError(t, err)
	require.Equal(t, 3, flaky.Calls())
	require.EqualValues(t, 42, resp.GetSlot())
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
