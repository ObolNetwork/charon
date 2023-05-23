// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/routing"
	"github.com/libp2p/go-libp2p/p2p/protocol/identify"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/lifecycle"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/app/z"
)

var activationThreshOnce = sync.Once{}

// NewTCPNode returns a started tcp-based libp2p host.
func NewTCPNode(ctx context.Context, cfg Config, key *k1.PrivateKey, connGater ConnGater,
	filterPrivateAddrs bool, opts ...libp2p.Option,
) (host.Host, error) {
	activationThreshOnce.Do(func() {
		// Use own observed addresses as soon as a single relay reports it.
		// Since there are probably no other directly connected peers to do so.
		identify.ActivationThresh = 1
	})

	addrs, err := cfg.Multiaddrs()
	if err != nil {
		return nil, err
	}

	if len(addrs) == 0 {
		log.Info(ctx, "LibP2P not accepting incoming connections since --p2p-tcp-addresses empty")
	}

	externalAddrs, err := externalMultiAddrs(cfg)
	if err != nil {
		return nil, err
	}

	var tcpOpts []interface{} // libp2p.Transport requires empty interface options.
	if cfg.DisableReuseport {
		tcpOpts = append(tcpOpts, tcp.DisableReuseport())
	}

	// Init options.
	defaultOpts := []libp2p.Option{
		// Set P2P identity key.
		libp2p.Identity((*crypto.Secp256k1PrivateKey)(key)),
		// Set TCP listen addresses.
		libp2p.ListenAddrs(addrs...),
		// Set up user-agent.
		libp2p.UserAgent("obolnetwork-charon/" + version.Version),
		// Limit connections to DV peers.
		libp2p.ConnectionGater(connGater),
		// Enable Autonat (required for hole punching)
		libp2p.EnableNATService(),
		libp2p.AddrsFactory(func(internalAddrs []ma.Multiaddr) []ma.Multiaddr {
			return filterAdvertisedAddrs(externalAddrs, internalAddrs, filterPrivateAddrs)
		}),
		libp2p.Transport(tcp.NewTCPTransport, tcpOpts...),
	}

	defaultOpts = append(defaultOpts, opts...)

	tcpNode, err := libp2p.New(defaultOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "new libp2p node")
	}

	return tcpNode, nil
}

// filterAdvertisedAddrs returns a unique set of external and internal addresses optionally excluding internal private addresses.
func filterAdvertisedAddrs(externalAddrs, internalAddrs []ma.Multiaddr, excludeInternalPrivate bool) []ma.Multiaddr {
	var (
		resp  []ma.Multiaddr
		dedup = make(map[string]bool)
	)
	add := func(addrs []ma.Multiaddr, excludePrivate bool) {
		for _, addr := range addrs {
			addrStr := addr.String()
			if dedup[addrStr] {
				continue
			}
			dedup[addrStr] = true

			if excludePrivate && manet.IsPrivateAddr(addr) {
				continue
			}
			resp = append(resp, addr)
		}
	}

	add(externalAddrs, false)
	add(internalAddrs, excludeInternalPrivate)

	return resp
}

// externalMultiAddrs returns the external IP and Hostname fields as multiaddrs using the listen TCP address ports.
func externalMultiAddrs(cfg Config) ([]ma.Multiaddr, error) {
	tcpAddrs, err := cfg.ParseTCPAddrs()
	if err != nil {
		return nil, err
	}

	var ports []int
	for _, addr := range tcpAddrs {
		ports = append(ports, addr.Port)
	}

	var resp []ma.Multiaddr

	if cfg.ExternalIP != "" {
		ip := net.ParseIP(cfg.ExternalIP)
		for _, port := range ports {
			maddr, err := multiAddrFromIPPort(ip, port)
			if err != nil {
				return nil, err
			}

			resp = append(resp, maddr)
		}
	}

	if cfg.ExternalHost != "" {
		for _, port := range ports {
			maddr, err := ma.NewMultiaddr(fmt.Sprintf("/dns/%s/tcp/%d", cfg.ExternalHost, port))
			if err != nil {
				return nil, errors.Wrap(err, "invalid dns multiaddr")
			}

			resp = append(resp, maddr)
		}
	}

	return resp, nil
}

// multiAddrsViaRelay returns multiaddrs to the peer via the relay.
// See https://github.com/libp2p/go-libp2p/blob/master/examples/relay/main.go.
func multiAddrsViaRelay(relayPeer Peer, peerID peer.ID) ([]ma.Multiaddr, error) {
	var resp []ma.Multiaddr
	for _, addr := range relayPeer.Addrs {
		transportAddr, _ := peer.SplitAddr(addr)

		addr := fmt.Sprintf("/p2p/%s/p2p-circuit/p2p/%s", relayPeer.ID, peerID)
		relayAddr, err := ma.NewMultiaddr(addr)
		if err != nil {
			return nil, errors.Wrap(err, "new multiaddr")
		}

		resp = append(resp, transportAddr.Encapsulate(relayAddr))
	}

	return resp, nil
}

// NewEventCollector returns a lifecycle hook that instruments libp2p events.
func NewEventCollector(tcpNode host.Host) lifecycle.HookFuncCtx {
	return func(ctx context.Context) {
		sub, err := tcpNode.EventBus().Subscribe(new(event.EvtLocalReachabilityChanged))
		if err != nil {
			log.Error(ctx, "Subscribe libp2p events", err)
			return
		}

		ctx = log.WithTopic(ctx, "p2p")
		reachableGauge.Set(float64(network.ReachabilityUnknown))

		for {
			select {
			case <-ctx.Done():
				return
			case e := <-sub.Out():
				switch evt := e.(type) {
				case event.EvtLocalReachabilityChanged:
					log.Info(ctx, "Libp2p reachability changed", z.Any("status", evt.Reachability))
					reachableGauge.Set(float64(evt.Reachability))
				default:
					log.Warn(ctx, "Unknown libp2p event", nil, z.Str("type", fmt.Sprintf("%T", e)))
				}
			}
		}
	}
}

// peerRoutingFunc wraps a function to implement routing.PeerRouting.
type peerRoutingFunc func(context.Context, peer.ID) (peer.AddrInfo, error)

func (f peerRoutingFunc) FindPeer(ctx context.Context, p peer.ID) (peer.AddrInfo, error) {
	return f(ctx, p)
}

// ForceDirectConnections attempts to establish a direct connection if there is an existing relay connection to the peer.
// The idea is to enable switching to a direct connection as soon as the host has a connection to the peer.
func ForceDirectConnections(tcpNode host.Host, peerIDs []peer.ID) lifecycle.HookFuncCtx {
	forceDirectConn := func(ctx context.Context) {
		for _, p := range peerIDs {
			if tcpNode.ID() == p {
				continue // Skip self
			}

			conns := tcpNode.Network().ConnsToPeer(p)
			directConn := false
			if len(conns) == 0 {
				// Skip if there isn't any existing connection to peer. Note that we only force direct connection
				// if there is already an existing relay connection between the host and peer.
				continue
			}

			for _, conn := range conns {
				if IsRelayAddr(conn.RemoteMultiaddr()) {
					continue
				}
				directConn = true

				break
			}

			if directConn {
				continue
			}

			// All existing connections are through relays, so we can try force dialing a direct connection.
			err := tcpNode.Connect(network.WithForceDirectDial(ctx, "relay_to_direct"), peer.AddrInfo{ID: p})
			if err == nil {
				log.Debug(ctx, "Forced direct connection to peer successful", z.Str("peer", PeerName(p)))
			}
		}
	}

	return func(ctx context.Context) {
		ticker := time.NewTicker(1 * time.Minute)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				forceDirectConn(ctx)
			}
		}
	}
}

// RegisterConnectionLogger registers a connection logger with the host.
// This is pretty weird and hacky, but that is because libp2p uses the network.Notifiee interface as a map key,
// so the implementation can only contain fields that are hashable. So we use a channel and do the logic externally. :(.
func RegisterConnectionLogger(ctx context.Context, tcpNode host.Host, peerIDs []peer.ID) {
	ctx = log.WithTopic(ctx, "p2p")

	type connKey struct {
		PeerName string
		Type     string
	}

	var (
		quit   = make(chan struct{})
		peers  = make(map[peer.ID]bool)
		events = make(chan logEvent)
		ticker = time.NewTicker(time.Second * 30)
	)

	for _, p := range peerIDs {
		peers[p] = true
	}

	tcpNode.Network().Notify(connLogger{
		events: events,
		quit:   quit,
	})

	go func() {
		defer close(quit)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Instrument connection counts.
				counts := make(map[connKey]int)
				for _, conn := range tcpNode.Network().Conns() {
					key := connKey{PeerName: PeerName(conn.RemotePeer()), Type: addrType(conn.RemoteMultiaddr())}
					counts[key]++
				}
				for _, pID := range peerIDs {
					for _, typ := range []string{addrTypeRelay, addrTypeDirect} {
						key := connKey{PeerName: PeerName(pID), Type: typ}
						peerConnGauge.WithLabelValues(key.PeerName, key.Type).Set(float64(counts[key]))
					}
				}
			case e := <-events:
				// Log and instrument events.
				addr := NamedAddr(e.Addr)
				name := PeerName(e.Peer)
				typ := addrType(e.Addr)

				if e.Listen {
					log.Debug(ctx, "Libp2p listening on address", z.Str("address", addr))
					continue
				} else if e.Connected {
					log.Debug(ctx, "Libp2p new connection",
						z.Str("peer", name),
						z.Any("peer_address", addr),
						z.Any("direction", e.Direction),
						z.Str("type", typ),
					)
				} else if e.Disconnect {
					log.Debug(ctx, "Libp2p disconnected",
						z.Str("peer", name),
						z.Any("peer_address", addr),
						z.Any("direction", e.Direction),
						z.Str("type", typ),
					)
				}

				if e.Connected && peers[e.Peer] { // Do not instrument relays.
					peerConnCounter.WithLabelValues(name).Inc()
				}
			}
		}
	}()
}

type logEvent struct {
	Peer       peer.ID
	Addr       ma.Multiaddr
	Direction  network.Direction
	ConnID     string
	Connected  bool
	Disconnect bool
	Listen     bool
}

// connLogger implements network.Notifiee and only sends logEvents on a channel since
// it is used as a map key internally in libp2p, it cannot contain complex types.
type connLogger struct {
	quit   chan struct{}
	events chan logEvent
}

func (l connLogger) Listen(_ network.Network, addr ma.Multiaddr) {
	select {
	case <-l.quit:
	case l.events <- logEvent{
		Addr:   addr,
		Listen: true,
	}:
	}
}

func (connLogger) ListenClose(network.Network, ma.Multiaddr) {}

func (l connLogger) Connected(_ network.Network, conn network.Conn) {
	select {
	case <-l.quit:
	case l.events <- logEvent{
		Peer:      conn.RemotePeer(),
		Addr:      conn.RemoteMultiaddr(),
		Direction: conn.Stat().Direction,
		Connected: true,
		ConnID:    conn.ID(),
	}:
	}
}

func (l connLogger) Disconnected(_ network.Network, conn network.Conn) {
	select {
	case <-l.quit:
	case l.events <- logEvent{
		Peer:       conn.RemotePeer(),
		Addr:       conn.RemoteMultiaddr(),
		Direction:  conn.Stat().Direction,
		Disconnect: true,
		ConnID:     conn.ID(),
	}:
	}
}

var (
	_ routing.PeerRouting = peerRoutingFunc(nil) // interface assertion
	_ network.Notifiee    = connLogger{}
)

// addrType returns 'direct' or 'relay' based on whether the address contains a relay.
func addrType(a ma.Multiaddr) string {
	if IsRelayAddr(a) {
		return addrTypeRelay
	}

	return addrTypeDirect
}

// IsRelayAddr returns true if the address is a relayed address.
// Copied from github.com/libp2p/go-libp2p@v0.22.0/p2p/protocol/circuitv2/relay/relay.go:593.
func IsRelayAddr(a ma.Multiaddr) bool {
	_, err := a.ValueForProtocol(ma.P_CIRCUIT)
	return err == nil
}
