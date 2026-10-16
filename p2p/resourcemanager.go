// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p

import (
	"net/netip"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	circuitproto "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/proto"
	relayv2 "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	"github.com/libp2p/go-libp2p/x/rate"

	"github.com/obolnetwork/charon/app/errors"
)

// Per-peer limits are fixed instead of autoscaled for deterministic behaviour across machines.
// Cluster peers are authenticated but not trusted: elevated limits accommodate duty load
// spikes while still bounding the damage a Byzantine peer can do. Other peers (relays)
// only require reservation and identify streams, so they get the default limits.
const (
	defaultPeerStreamsInbound  = 512
	defaultPeerStreamsOutbound = 1024
	defaultPeerConns           = 16
	defaultPeerMemory          = 64 << 20

	clusterPeerStreamsInbound  = 4096
	clusterPeerStreamsOutbound = 4096
	clusterPeerConns           = 32
	clusterPeerMemory          = 512 << 20

	// clusterConnsPerIP limits connections per remote IP while still allowing
	// multiple cluster peers to share one IP (NAT or local test clusters).
	clusterConnsPerIP = 64

	// System and transient stream and connection limits are fixed for the same reason
	// as the per-peer limits. go-libp2p's autoscaled defaults are derived from an
	// eighth of host memory and fall below the per-peer limits on typical validator
	// hardware (3072 inbound streams and 64 transient inbound connections on a 16GB
	// host, less below that), which makes the per-peer allowances unreachable and the
	// effective limits depend on host memory. Memory and FD limits stay host derived,
	// since those track resources the host actually has.
	//
	// transientConns bounds connections that have not yet negotiated a protocol. It
	// exceeds clusterConnsPerIP so a cluster sharing one NAT IP can reconnect in a
	// single burst, matching the connection rate limiter burst.
	transientConns = 2 * clusterConnsPerIP

	// The system scope stays above the per-peer limits so no single peer can exhaust
	// it: 16384 inbound streams is four cluster peers' worth. Connections are sized
	// against the transient scope instead, because a pending connection holds a
	// transient and a system reservation until it identifies, so the system scope must
	// admit a full transient burst alongside established peers.
	systemStreamsInbound  = 4 * clusterPeerStreamsInbound
	systemStreamsOutbound = 4 * clusterPeerStreamsOutbound
	systemConns           = 2 * transientConns

	// relayServiceMemory bounds the circuit relay scopes, covering per-circuit
	// buffers at full circuit load.
	relayServiceMemory = 512 << 20
)

// NewResourceManager returns a libp2p resource manager for charon nodes.
// Stream and connection limits are fixed, with elevated limits for the
// authenticated cluster peers, while memory and FD limits scale with the host.
func NewResourceManager(clusterPeers []peer.ID) (network.ResourceManager, error) {
	rm, err := rcmgr.NewResourceManager(
		rcmgr.NewFixedLimiter(clusterLimitConfig(clusterPeers)),
		rcmgr.WithLimitPerSubnet(
			[]rcmgr.ConnLimitPerSubnet{{ConnCount: clusterConnsPerIP, PrefixLength: 32}},
			[]rcmgr.ConnLimitPerSubnet{{ConnCount: clusterConnsPerIP, PrefixLength: 56}},
		),
		rcmgr.WithConnRateLimiters(newConnRateLimiter(clusterConnsPerIP)),
	)
	if err != nil {
		return nil, errors.Wrap(err, "new resource manager")
	}

	return rm, nil
}

// NewRelayResourceManager returns a libp2p resource manager for relay nodes.
// System connection limits are derived from the relay connection config while
// other limits scale with available memory.
func NewRelayResourceManager(maxConns, maxConnsPerIP int) (network.ResourceManager, error) {
	rm, err := rcmgr.NewResourceManager(
		rcmgr.NewFixedLimiter(relayLimitConfig(maxConns, maxConnsPerIP)),
		rcmgr.WithLimitPerSubnet(
			[]rcmgr.ConnLimitPerSubnet{{ConnCount: maxConnsPerIP, PrefixLength: 32}},
			[]rcmgr.ConnLimitPerSubnet{{ConnCount: maxConnsPerIP, PrefixLength: 56}},
		),
		rcmgr.WithConnRateLimiters(newConnRateLimiter(maxConnsPerIP)),
	)
	if err != nil {
		return nil, errors.Wrap(err, "new relay resource manager")
	}

	return rm, nil
}

// clusterLimitConfig returns charon node resource limits: fixed system, transient and
// per-peer stream and connection limits, with elevated allowances for cluster peers.
// Memory and FD limits are left at their host derived defaults.
func clusterLimitConfig(clusterPeers []peer.ID) rcmgr.ConcreteLimitConfig {
	limits := rcmgr.DefaultLimits
	libp2p.SetDefaultServiceLimits(&limits)

	clusterLimits := make(map[peer.ID]rcmgr.ResourceLimits, len(clusterPeers))
	for _, pID := range clusterPeers {
		clusterLimits[pID] = peerLimits(clusterPeerStreamsInbound, clusterPeerStreamsOutbound, clusterPeerConns, clusterPeerMemory)
	}

	cfg := rcmgr.PartialLimitConfig{
		System: rcmgr.ResourceLimits{
			StreamsInbound:  systemStreamsInbound,
			StreamsOutbound: systemStreamsOutbound,
			Streams:         systemStreamsInbound + systemStreamsOutbound,
			ConnsInbound:    systemConns,
			ConnsOutbound:   systemConns,
			Conns:           2 * systemConns,
		},
		Transient: rcmgr.ResourceLimits{
			ConnsInbound:  transientConns,
			ConnsOutbound: transientConns,
			Conns:         2 * transientConns,
		},
		PeerDefault: peerLimits(defaultPeerStreamsInbound, defaultPeerStreamsOutbound, defaultPeerConns, defaultPeerMemory),
		Peer:        clusterLimits,
		// All charon protocols share the default protocol limits, so raise them to
		// match the system and cluster peer limits in both directions; the peer and
		// system scopes remain the effective bounds.
		ProtocolDefault:     streamLimits(systemStreamsInbound, systemStreamsOutbound),
		ProtocolPeerDefault: streamLimits(clusterPeerStreamsInbound, clusterPeerStreamsOutbound),
	}

	return cfg.Build(limits.AutoScale())
}

// relayLimitConfig returns relay resource limits derived from the relay connection config.
func relayLimitConfig(maxConns, maxConnsPerIP int) rcmgr.ConcreteLimitConfig {
	limits := rcmgr.DefaultLimits
	libp2p.SetDefaultServiceLimits(&limits)

	// Each relayed circuit costs an inbound and an outbound stream on the relay,
	// plus reservation and identify streams, so allow multiple streams per connection.
	maxStreams := 4 * maxConns

	systemLimits := rcmgr.ResourceLimits{
		Conns:           rcmgr.LimitVal(maxConns),
		ConnsInbound:    rcmgr.LimitVal(maxConns),
		FD:              rcmgr.LimitVal(maxConns),
		Streams:         rcmgr.LimitVal(maxStreams),
		StreamsInbound:  rcmgr.LimitVal(maxStreams),
		StreamsOutbound: rcmgr.LimitVal(maxStreams),
	}

	// The circuit relay protocol and service scopes must also track the connection
	// config: their go-libp2p defaults scale with host memory and would otherwise
	// cap circuits well below the configured connection limits.
	relayStreams := rcmgr.ResourceLimits{
		Streams:         rcmgr.LimitVal(maxStreams),
		StreamsInbound:  rcmgr.LimitVal(maxStreams),
		StreamsOutbound: rcmgr.LimitVal(maxStreams),
		Memory:          relayServiceMemory,
	}
	// The relay allows maxConnsPerIP circuit reservations per peer, each costing an
	// inbound and an outbound stream.
	relayPeerStreams := streamLimits(2*maxConnsPerIP, 2*maxConnsPerIP)

	cfg := rcmgr.PartialLimitConfig{
		System: systemLimits,
		// Match transient limits to system limits so reconnect storms
		// (e.g. after a relay restart) are not throttled below capacity.
		Transient: systemLimits,
		Protocol: map[protocol.ID]rcmgr.ResourceLimits{
			circuitproto.ProtoIDv2Hop:  relayStreams,
			circuitproto.ProtoIDv2Stop: relayStreams,
		},
		ProtocolPeer: map[protocol.ID]rcmgr.ResourceLimits{
			circuitproto.ProtoIDv2Hop:  relayPeerStreams,
			circuitproto.ProtoIDv2Stop: relayPeerStreams,
		},
		Service: map[string]rcmgr.ResourceLimits{
			relayv2.ServiceName: relayStreams,
		},
		ServicePeer: map[string]rcmgr.ResourceLimits{
			relayv2.ServiceName: relayPeerStreams,
		},
	}

	return cfg.Build(limits.AutoScale())
}

// newConnRateLimiter returns a connection rate limiter allowing bursts up to twice
// the per-IP connection limit. It replaces go-libp2p's default which caps bursts at
// 16 connections per IP regardless of the configured connection limits, throttling
// legitimate reconnect storms from peers sharing a NAT IP.
func newConnRateLimiter(perIPConns int) *rate.Limiter {
	rps := float64(perIPConns)

	return &rate.Limiter{
		// Never rate limit loopback.
		NetworkPrefixLimits: []rate.PrefixLimit{
			{Prefix: netip.MustParsePrefix("127.0.0.0/8"), Limit: rate.Limit{}},
			{Prefix: netip.MustParsePrefix("::1/128"), Limit: rate.Limit{}},
		},
		SubnetRateLimiter: rate.SubnetLimiter{
			IPv4SubnetLimits: []rate.SubnetLimit{
				{PrefixLength: 32, Limit: rate.Limit{RPS: rps, Burst: 2 * perIPConns}},
			},
			IPv6SubnetLimits: []rate.SubnetLimit{
				{PrefixLength: 56, Limit: rate.Limit{RPS: rps, Burst: 2 * perIPConns}},
				{PrefixLength: 48, Limit: rate.Limit{RPS: 4 * rps, Burst: 8 * perIPConns}},
			},
			GracePeriod: time.Minute,
		},
	}
}

// streamLimits returns fixed stream-only resource limits, leaving other resources at their defaults.
func streamLimits(inbound, outbound int) rcmgr.ResourceLimits {
	return rcmgr.ResourceLimits{
		StreamsInbound:  rcmgr.LimitVal(inbound),
		StreamsOutbound: rcmgr.LimitVal(outbound),
		Streams:         rcmgr.LimitVal(inbound + outbound),
	}
}

// peerLimits returns fixed per-peer resource limits.
func peerLimits(streamsInbound, streamsOutbound, conns int, memory int64) rcmgr.ResourceLimits {
	return rcmgr.ResourceLimits{
		StreamsInbound:  rcmgr.LimitVal(streamsInbound),
		StreamsOutbound: rcmgr.LimitVal(streamsOutbound),
		Streams:         rcmgr.LimitVal(streamsInbound + streamsOutbound),
		ConnsInbound:    rcmgr.LimitVal(conns),
		ConnsOutbound:   rcmgr.LimitVal(conns),
		Conns:           rcmgr.LimitVal(conns),
		FD:              rcmgr.LimitVal(conns),
		Memory:          rcmgr.LimitVal64(memory),
	}
}
