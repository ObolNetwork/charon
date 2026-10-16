// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p

import (
	"fmt"
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	circuitproto "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/proto"
	relayv2 "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

// openInboundStreams opens inbound streams for the given peer until the resource
// manager rejects one, returning the number of streams opened.
func openInboundStreams(t *testing.T, rm network.ResourceManager, pID peer.ID, maxAttempts int) int {
	t.Helper()

	var scopes []network.StreamManagementScope

	t.Cleanup(func() {
		for _, scope := range scopes {
			scope.Done()
		}
	})

	for i := range maxAttempts {
		scope, err := rm.OpenStream(pID, network.DirInbound)
		if err != nil {
			return i
		}

		scopes = append(scopes, scope)

		// Attach a protocol like negotiated streams do, moving the stream
		// from the transient scope to the protocol and peer scopes.
		require.NoError(t, scope.SetProtocol("/charon/test"))
	}

	return maxAttempts
}

func randomPeerID(t *testing.T) peer.ID {
	t.Helper()

	key, err := k1.GeneratePrivateKey()
	require.NoError(t, err)

	pID, err := PeerIDFromKey(key.PubKey())
	require.NoError(t, err)

	return pID
}

func TestNewResourceManagerPeerStreamLimits(t *testing.T) {
	clusterPeer := randomPeerID(t)
	unknownPeer := randomPeerID(t)

	rm, err := NewResourceManager([]peer.ID{clusterPeer})
	require.NoError(t, err)

	defer rm.Close()

	// Unknown peers (e.g. relays) get the fixed default limit.
	unknownStreams := openInboundStreams(t, rm, unknownPeer, defaultPeerStreamsInbound*2)
	require.Equal(t, defaultPeerStreamsInbound, unknownStreams)

	// Cluster peers get elevated but still bounded limits.
	clusterStreams := openInboundStreams(t, rm, clusterPeer, clusterPeerStreamsInbound*2)
	require.Equal(t, clusterPeerStreamsInbound, clusterStreams)
}

func TestNewRelayResourceManagerConnLimits(t *testing.T) {
	const (
		maxConns      = 64
		maxConnsPerIP = 4
	)

	rm, err := NewRelayResourceManager(maxConns, maxConnsPerIP)
	require.NoError(t, err)

	defer rm.Close()

	openConn := func(rm network.ResourceManager, addr string) (network.ConnManagementScope, error) {
		return rm.OpenConnection(network.DirInbound, false, ma.StringCast(addr))
	}

	// Connections from distinct IPs are allowed up to maxConns system-wide.
	var scopes []network.ConnManagementScope

	defer func() {
		for _, scope := range scopes {
			scope.Done()
		}
	}()

	for i := range maxConns {
		scope, err := openConn(rm, fmt.Sprintf("/ip4/10.0.%d.%d/tcp/1234", i/256+1, i%256))
		require.NoError(t, err)

		scopes = append(scopes, scope)
	}

	_, err = openConn(rm, "/ip4/10.99.99.99/tcp/1234")
	require.Error(t, err)

	// Connections from a single IP are limited to maxConnsPerIP.
	rm2, err := NewRelayResourceManager(maxConns, maxConnsPerIP)
	require.NoError(t, err)

	defer rm2.Close()

	for range maxConnsPerIP {
		scope, err := openConn(rm2, "/ip4/10.1.1.1/tcp/1234")
		require.NoError(t, err)

		defer scope.Done()
	}

	_, err = openConn(rm2, "/ip4/10.1.1.1/tcp/1234")
	require.Error(t, err)
}

// TestConnRateLimiterAllowsPerIPBurst ensures the connection rate limiter permits
// a rapid burst of connections up to the per-IP connection limit, e.g. when
// multiple peers behind one NAT IP reconnect after a relay restart.
func TestConnRateLimiterAllowsPerIPBurst(t *testing.T) {
	const (
		maxConns      = 128
		maxConnsPerIP = 32 // Above go-libp2p's default rate limiter burst of 16.
	)

	openConns := func(t *testing.T, rm network.ResourceManager, addr string, n int) {
		t.Helper()

		for range n {
			scope, err := rm.OpenConnection(network.DirInbound, false, ma.StringCast(addr))
			require.NoError(t, err)

			defer scope.Done()
		}
	}

	rm, err := NewRelayResourceManager(maxConns, maxConnsPerIP)
	require.NoError(t, err)

	defer rm.Close()

	openConns(t, rm, "/ip4/10.2.2.2/tcp/1234", maxConnsPerIP)

	// Validator nodes similarly allow bursts up to the per-IP limit.
	clusterRM, err := NewResourceManager(nil)
	require.NoError(t, err)

	defer clusterRM.Close()

	openConns(t, clusterRM, "/ip4/10.2.2.2/tcp/1234", clusterConnsPerIP)
}

// TestClusterLimitConfig ensures system and transient stream and connection limits
// are fixed instead of scaling with host memory, and that they leave room for the
// per-peer limits, which would otherwise be unreachable on smaller hosts.
func TestClusterLimitConfig(t *testing.T) {
	cfg := clusterLimitConfig([]peer.ID{randomPeerID(t)}).ToPartialLimitConfig()

	require.Equal(t, rcmgr.LimitVal(systemStreamsInbound), cfg.System.StreamsInbound)
	require.Equal(t, rcmgr.LimitVal(systemConns), cfg.System.ConnsInbound)
	require.Equal(t, rcmgr.LimitVal(transientConns), cfg.Transient.ConnsInbound)

	// The system scope must exceed a single peer's allowance so no one peer can
	// exhaust it, and the transient scope must admit a full per-IP connection burst.
	require.Greater(t, cfg.System.StreamsInbound, rcmgr.LimitVal(clusterPeerStreamsInbound))
	require.Greater(t, cfg.System.ConnsInbound, rcmgr.LimitVal(clusterPeerConns))
	require.Greater(t, cfg.Transient.ConnsInbound, rcmgr.LimitVal(clusterConnsPerIP))

	// Memory stays host derived, bounding aggregate load on small hosts.
	require.Equal(t, rcmgr.LimitVal64(defaultPeerMemory), cfg.PeerDefault.Memory)
	require.NotZero(t, cfg.System.Memory)
}

// TestRelayLimitConfig ensures relay capacity limits derive from the relay
// connection config instead of scaling with host memory.
func TestRelayLimitConfig(t *testing.T) {
	const (
		maxConns      = 16384
		maxConnsPerIP = 512
	)

	cfg := relayLimitConfig(maxConns, maxConnsPerIP).ToPartialLimitConfig()

	maxStreams := rcmgr.LimitVal(4 * maxConns)
	perPeerStreams := rcmgr.LimitVal(2 * maxConnsPerIP)

	require.Equal(t, rcmgr.LimitVal(maxConns), cfg.System.ConnsInbound)
	require.Equal(t, maxStreams, cfg.System.StreamsInbound)

	// Circuit relay protocol and service scopes must accommodate full circuit load.
	for _, proto := range []protocol.ID{circuitproto.ProtoIDv2Hop, circuitproto.ProtoIDv2Stop} {
		require.Equal(t, maxStreams, cfg.Protocol[proto].StreamsInbound, proto)
		require.Equal(t, perPeerStreams, cfg.ProtocolPeer[proto].StreamsInbound, proto)
	}

	require.Equal(t, maxStreams, cfg.Service[relayv2.ServiceName].StreamsInbound)
	require.Equal(t, perPeerStreams, cfg.ServicePeer[relayv2.ServiceName].StreamsInbound)
}
