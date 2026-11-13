// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p_test

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/proto"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/relay"
)

func TestRelayHasReservation(t *testing.T) {
	ctx := t.Context()

	relayURL := relay.StartRelay(ctx, t)

	relays, err := p2p.NewRelays(ctx, []string{relayURL}, "lockhash", "uuid")
	require.NoError(t, err)
	require.Len(t, relays, 1)

	relayPeer, ok := relays[0].Peer()
	require.True(t, ok)

	info := relayPeer.AddrInfo()

	// The reserving host owns key K; the probe must work without it.
	h := testutil.CreateHost(t, testutil.AvailableAddr(t))
	defer h.Close()

	has, err := p2p.RelayHasReservation(ctx, info, h.ID())
	require.NoError(t, err)
	require.False(t, has)

	require.NoError(t, h.Connect(ctx, peer.AddrInfo{ID: info.ID, Addrs: info.Addrs}))

	_, err = client.Reserve(ctx, h, info)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		has, err := p2p.RelayHasReservation(ctx, info, h.ID())
		return err == nil && has
	}, 5*time.Second, 100*time.Millisecond)
}

func TestRelayHasReservationCtx(t *testing.T) {
	// A fake relay that accepts the hop stream and never answers.
	fake := testutil.CreateHost(t, testutil.AvailableAddr(t))
	defer fake.Close()

	fake.SetStreamHandler(proto.ProtoIDv2Hop, func(s network.Stream) {
		<-t.Context().Done()

		_ = s.Reset()
	})

	info := peer.AddrInfo{ID: fake.ID(), Addrs: fake.Addrs()}
	fake.Peerstore().AddAddrs(fake.ID(), fake.Addrs(), peerstore.PermanentAddrTTL)

	target := testutil.CreateHost(t, testutil.AvailableAddr(t))
	defer target.Close()

	t.Run("deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
		defer cancel()

		start := time.Now()
		has, err := p2p.RelayHasReservation(ctx, info, target.ID())
		require.Error(t, err)
		require.False(t, has)
		require.Less(t, time.Since(start), 5*time.Second)
	})

	t.Run("cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		time.AfterFunc(300*time.Millisecond, cancel)

		start := time.Now()
		has, err := p2p.RelayHasReservation(ctx, info, target.ID())
		require.Error(t, err)
		require.False(t, has)
		require.Less(t, time.Since(start), 5*time.Second)
	})
}
