// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p

import (
	"context"
	"fmt"
	"math"
	"net"
	"slices"
	"sync"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/routing"
	"github.com/libp2p/go-libp2p/p2p/protocol/identify"
	quic "github.com/libp2p/go-libp2p/p2p/transport/quic" //nolint:revive // Must be imported with alias
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

type NodeType int

const (
	NodeTypeTCP NodeType = iota
	NodeTypeQUIC
)

// NewP2PNode returns a started libp2p host.
func NewNode(ctx context.Context, cfg Config, key *k1.PrivateKey, connGater ConnGater,
	filterPrivateAddrs bool, nodeType NodeType, opts ...libp2p.Option,
) (host.Host, error) {
	activationThreshOnce.Do(func() {
		// Use own observed addresses as soon as a single relay reports it.
		// Since there are probably no other directly connected peers to do so.
		identify.ActivationThresh = 1
	})

	var libP2POpts []any // libp2p.Transport requires empty interface options.
	if cfg.DisableReuseport {
		libP2POpts = append(libP2POpts, tcp.DisableReuseport())
	}

	addrs, err := cfg.TCPMultiaddrs()
	if err != nil {
		return nil, err
	}

	if len(addrs) == 0 {
		log.Info(ctx, "LibP2P not accepting incoming connections since --p2p-tcp-addresses is empty")
	}

	externalAddrs, err := externalTCPMultiAddrs(cfg)
	if err != nil {
		return nil, err
	}

	transport := libp2p.Transport(tcp.NewTCPTransport, libP2POpts...)

	// Use both QUIC and TCP transport when QUIC is enabled, as we are accommodating both connections in the cases where QUIC is enabled.
	if nodeType == NodeTypeQUIC {
		udpAddrs, err := cfg.UDPMultiaddrs()
		if err != nil {
			return nil, err
		}

		if len(udpAddrs) == 0 {
			log.Warn(ctx, "LibP2P QUIC enabled but --p2p-udp-addresses is empty", nil)
		}

		addrs = append(addrs, udpAddrs...)
		if len(addrs) == 0 {
			log.Warn(ctx, "LibP2P not accepting incoming connections since --p2p-udp-addresses and --p2p-tcp-addresses are empty", nil)
		}

		externalUDPAddrs, err := externalUDPMultiAddrs(cfg)
		if err != nil {
			return nil, err
		}

		externalAddrs = append(externalAddrs, externalUDPAddrs...)

		transport = libp2p.ChainOptions(
			transport,
			libp2p.Transport(quic.NewTransport),
		)
	}

	// Init options.
	defaultOpts := []libp2p.Option{
		// Set P2P identity key.
		libp2p.Identity((*crypto.Secp256k1PrivateKey)(key)),
		// Set UDP listen addresses.
		libp2p.ListenAddrs(addrs...),
		// Set up user-agent.
		libp2p.UserAgent("obolnetwork-charon/" + version.Version.String()),
		// Limit connections to DV peers.
		libp2p.ConnectionGater(connGater),
		// Enable Autonat (required for hole punching)
		libp2p.EnableNATService(),
		libp2p.AddrsFactory(func(internalAddrs []ma.Multiaddr) []ma.Multiaddr {
			return filterAdvertisedAddrs(externalAddrs, internalAddrs, filterPrivateAddrs)
		}),
		transport,
	}

	defaultOpts = append(defaultOpts, opts...)

	p2pNode, err := libp2p.New(defaultOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "new libp2p node")
	}

	return p2pNode, nil
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

// externalUDPMultiAddrs returns the external IP and Hostname fields as multiaddrs using the listen UDP address ports.
func externalUDPMultiAddrs(cfg Config) ([]ma.Multiaddr, error) {
	addrs, err := cfg.ParseUDPAddrs()
	if err != nil {
		return nil, err
	}

	var ports []int
	for _, addr := range addrs {
		ports = append(ports, addr.Port)
	}

	var resp []ma.Multiaddr

	if cfg.ExternalIP != "" {
		ip := net.ParseIP(cfg.ExternalIP)
		for _, port := range ports {
			maddr, err := multiAddrFromIPUDPPort(ip, port)
			if err != nil {
				return nil, err
			}

			resp = append(resp, maddr)
		}
	}

	if cfg.ExternalHost != "" {
		for _, port := range ports {
			maddr, err := ma.NewMultiaddr(fmt.Sprintf("/dns/%s/udp/%d/quic-v1", cfg.ExternalHost, port))
			if err != nil {
				return nil, errors.Wrap(err, "invalid dns quic-v1 multiaddr")
			}

			resp = append(resp, maddr)
		}
	}

	return resp, nil
}

// externalTCPMultiAddrs returns the external IP and Hostname fields as multiaddrs using the listen TCP address ports.
func externalTCPMultiAddrs(cfg Config) ([]ma.Multiaddr, error) {
	addrs, err := cfg.ParseTCPAddrs()
	if err != nil {
		return nil, err
	}

	var ports []int
	for _, addr := range addrs {
		ports = append(ports, addr.Port)
	}

	var resp []ma.Multiaddr

	if cfg.ExternalIP != "" {
		ip := net.ParseIP(cfg.ExternalIP)
		for _, port := range ports {
			maddr, err := multiAddrFromIPTCPPort(ip, port)
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
				return nil, errors.Wrap(err, "invalid dns tcp multiaddr")
			}

			resp = append(resp, maddr)
		}
	}

	return resp, nil
}

// multiAddrsViaRelay returns multiaddrs to the peer via the relay.
// See https://github.com/libp2p/go-libp2p/blob/master/examples/relay/main.go.
func multiAddrsViaRelay(relayPeer Peer, peerID peer.ID) ([]ma.Multiaddr, error) {
	var addrs []ma.Multiaddr

	for _, addr := range relayPeer.Addrs {
		transportAddr, _ := peer.SplitAddr(addr)

		addr := fmt.Sprintf("/p2p/%s/p2p-circuit/p2p/%s", relayPeer.ID, peerID)

		relayAddr, err := ma.NewMultiaddr(addr)
		if err != nil {
			return nil, errors.Wrap(err, "new multiaddr")
		}

		addrs = append(addrs, transportAddr.Encapsulate(relayAddr))
	}

	return addrs, nil
}

// NewEventCollector returns a lifecycle hook that instruments libp2p events.
func NewEventCollector(p2pNode host.Host) lifecycle.HookFuncCtx {
	return func(ctx context.Context) {
		sub, err := p2pNode.EventBus().Subscribe(new(event.EvtLocalReachabilityChanged))
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
func ForceDirectConnections(p2pNode host.Host, peerIDs []peer.ID) lifecycle.HookFuncCtx {
	forceDirectConn := func(ctx context.Context) {
		for _, p := range peerIDs {
			if p2pNode.ID() == p {
				continue // Skip self
			}

			conns := p2pNode.Network().ConnsToPeer(p)
			if len(conns) == 0 {
				// Skip if there isn't any existing connection to peer. Note that we only force direct connection
				// if there is already an existing relay connection between the host and peer.
				continue
			}

			if isDirectConnAvailable(conns) {
				continue
			}

			// All existing connections are through relays, so we can try force dialing a direct connection.
			err := p2pNode.Connect(network.WithForceDirectDial(ctx, "relay_to_direct"), peer.AddrInfo{ID: p})
			if err == nil {
				log.Debug(ctx, "Forced direct connection to peer successful", z.Str("peer", PeerName(p)))
			}
		}
	}

	return func(ctx context.Context) {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

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

// IsQUICEnabled returns true if the host has an address or listening address on QUIC
func isQUICEnabled(h host.Host) bool {
	if slices.ContainsFunc(h.Network().ListenAddresses(), isQUICAddr) {
		return true
	}

	if addrs := h.Addrs(); len(addrs) > 0 {
		if slices.ContainsFunc(addrs, isQUICAddr) {
			return true
		}
	}

	return false
}

// isDirectConnAvailable returns true if direct connection is available in the given set of connections.
func isDirectConnAvailable(conns []network.Conn) bool {
	for _, conn := range conns {
		if IsRelayAddr(conn.RemoteMultiaddr()) {
			continue
		}

		return true
	}

	return false
}

// UpgradeToQUICConnections tries to upgrade a direct TCP connection to a direct QUIC connection
// if there is known QUIC addresses from the peerstore.
func UpgradeToQUICConnections(p2pNode host.Host, peerIDs []peer.ID) lifecycle.HookFuncCtx {
	type quicUpgradeBackoff struct {
		tickersRemaining int
		backoffDuration  int // in minutes/tickers
	}

	failedUpgradeAttempts := make(map[peer.ID]*quicUpgradeBackoff)

	var backoffMutex sync.Mutex

	recordUpgradeFailure := func(peerID peer.ID) {
		backoffMutex.Lock()
		defer backoffMutex.Unlock()

		if currentBackoff, exists := failedUpgradeAttempts[peerID]; exists {
			currentBackoff.backoffDuration = int(math.Min(float64(currentBackoff.backoffDuration*2), 512)) // max 8 hours
			currentBackoff.tickersRemaining = currentBackoff.backoffDuration
		} else {
			failedUpgradeAttempts[peerID] = &quicUpgradeBackoff{
				tickersRemaining: 2,
				backoffDuration:  2,
			}
		}
	}

	shouldSkipUpgradeAttempt := func(ctx context.Context, peerID peer.ID) bool {
		backoffMutex.Lock()
		defer backoffMutex.Unlock()

		if currentBackoff, exists := failedUpgradeAttempts[peerID]; exists {
			if currentBackoff.tickersRemaining > 0 {
				currentBackoff.tickersRemaining--
				log.Debug(ctx, "Skipping QUIC upgrade due to backoff", z.Str("peer", PeerName(peerID)), z.Int("tickers_remaining", currentBackoff.tickersRemaining), z.Int("backoff_duration_minutes", currentBackoff.backoffDuration))

				return true
			}

			return false
		}

		return false
	}

	clearUpgradeBackoff := func(peerID peer.ID) {
		backoffMutex.Lock()
		defer backoffMutex.Unlock()

		delete(failedUpgradeAttempts, peerID)
	}

	forceQUICConn := func(ctx context.Context) {
		if !isQUICEnabled(p2pNode) {
			log.Debug(ctx, "Node doesn't have feature QUIC enabled")
			return // doesn't support QUIC
		}

		for _, p := range peerIDs {
			if p2pNode.ID() == p {
				continue // skip self
			}

			if shouldSkipUpgradeAttempt(ctx, p) {
				continue // skip this peer due to active backoff
			}

			conns := p2pNode.Network().ConnsToPeer(p)
			if len(conns) == 0 {
				log.Debug(ctx, "No connection to peer", z.Str("peer", PeerName(p)))
				continue // nothing to upgrade
			}

			if hasDirectQUICConn(conns) {
				log.Debug(ctx, "Already has direct QUIC connection to peer", z.Str("peer", PeerName(p)), z.Any("conns", conns))

				// Remove unwanted TCP connections
				for _, conn := range conns {
					addr := conn.RemoteMultiaddr()
					if isTCPAddr(addr) {
						err := conn.Close()
						if err != nil {
							log.Debug(ctx, "Failed to closed redundant TCP connection", z.Str("peer", PeerName(p)), z.Any("addr", addr))
						} else {
							log.Debug(ctx, "Closed redundant TCP connection", z.Str("peer", PeerName(p)), z.Any("addr", addr))
						}
					}
				}

				continue // no need to upgrade
			}

			if !hasDirectTCPConn(conns) {
				log.Debug(ctx, "No direct connection via TCP to peer", z.Str("peer", PeerName(p)), z.Any("conns", conns))
				continue // no direct TPC connection to upgrade to QUIC, ForceDirectConnections shall upgrade to direct
			}

			// Get known QUIC addrs from peerstore
			var quicAddrs []ma.Multiaddr

			for _, addr := range p2pNode.Peerstore().Addrs(p) {
				if isQUICAddr(addr) && !isRelayAddr(addr) {
					quicAddrs = append(quicAddrs, addr)
				}
			}

			if len(quicAddrs) == 0 {
				log.Debug(ctx, "No knonw QUIC addresses to peer", z.Str("peer", PeerName(p)), z.Any("conns", conns))
				continue // no known QUIC addresses
			}

			log.Debug(ctx, "Trying to upgrade to QUIC connection with peer", z.Str("peer", PeerName(p)))

			// To maximize change of connectia via QUIC clear peerstore of TCP addresses
			originalPeerstore := slices.Clone(p2pNode.Peerstore().Addrs(p))
			p2pNode.Peerstore().ClearAddrs(p)
			p2pNode.Peerstore().AddAddrs(p, quicAddrs, peerstore.PermanentAddrTTL)

			t0 := time.Now() // t0: Start closing connections.
			// Close previous direct connections to ensure that we can establish a QUIC connection
			for _, conn := range conns {
				addr := conn.RemoteMultiaddr()
				if !isRelayAddr(addr) {
					log.Debug(ctx, "Closing connection during QUIC upgrade", z.Str("peer", PeerName(p)), z.Any("conn", conn))

					err := conn.Close()
					if err != nil {
						log.Debug(ctx, "Failed to close connections before upgrading to QUIC", z.Err(err), z.Any("addr", addr), z.Any("connection", conn))
					}
				}
			}

			t1 := time.Now() // t1: Finished closing. Start connecting. From t1 to t2 node will be disconnected.
			// Attempt to connect over QUIC
			// In case of QUIC failure due to infrastructure error (e.g. UDP port closed) the Connect call
			// may fail or succeed. It can succeed if another peer calls Connect to this peer with a working
			// TCP address which is misleading to us
			// If it fails, we try to reconnect via any available address
			// If it succeeds, we check whether we are actually connected via QUIC
			err := p2pNode.Connect(network.WithForceDirectDial(ctx, ""), peer.AddrInfo{ID: p})
			t2 := time.Now() // t2: Finished connecting.

			if err != nil {
				recordUpgradeFailure(p)
				log.Debug(ctx, "Failed to connect to peer during QUIC upgrade. Reconnecting via any address", z.Str("peer", PeerName(p)), z.Any("peerstore", p2pNode.Peerstore().Addrs(p)), z.Err(err))

				// Restore original peerstore
				p2pNode.Peerstore().AddAddrs(p, originalPeerstore, peerstore.PermanentAddrTTL)
				// Reconnect (probably through TCP)
				err := p2pNode.Connect(network.WithForceDirectDial(ctx, ""), peer.AddrInfo{ID: p})
				if err != nil {
					log.Debug(ctx, "Failed to establish connection after failed QUIC upgrade", z.Str("peer", PeerName(p)), z.Any("peerstore", p2pNode.Peerstore().Addrs(p)))
				}

				continue
			}

			// Restore original peerstore
			p2pNode.Peerstore().AddAddrs(p, originalPeerstore, peerstore.PermanentAddrTTL)

			// Confirm connection
			connectedViaQUIC := false

			for _, conn := range p2pNode.Network().ConnsToPeer(p) {
				addr := conn.RemoteMultiaddr()
				if !isRelayAddr(addr) {
					if isQUICAddr(addr) {
						connectedViaQUIC = true

						log.Debug(ctx, "Upgraded connection to QUIC", z.Str("peer", PeerName(p)), z.Any("closing_period", t1.Sub(t0)), z.Any("connecting_period", t2.Sub(t1)), z.Any("addr", addr), z.Any("direction", conn.Stat().Direction))
					} else if isTCPAddr(addr) {
						log.Debug(ctx, "Connected via TCP after upgrade to QUIC connection", z.Str("peer", PeerName(p)), z.Any("addr", addr), z.Any("direction", conn.Stat().Direction))
					}
				}
			}

			if !connectedViaQUIC {
				log.Debug(ctx, "Failed to establish direct connection via QUIC to peer", z.Str("peer", PeerName(p)), z.Any("closing_period", t1.Sub(t0)), z.Any("connecting_period", t2.Sub(t1)), z.Any("conns", p2pNode.Network().ConnsToPeer(p)), z.Any("peerstore", p2pNode.Peerstore().Addrs(p)))
				recordUpgradeFailure(p)
			} else {
				clearUpgradeBackoff(p)
			}
		}
	}

	return func(ctx context.Context) {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				forceQUICConn(ctx)
			}
		}
	}
}

// hasDirectTCPConn returns true if there's already a direct TCP connection among the given conns.
func hasDirectTCPConn(conns []network.Conn) bool {
	for _, conn := range conns {
		if isTCPAddr(conn.RemoteMultiaddr()) && !isRelayAddr(conn.RemoteMultiaddr()) {
			return true
		}
	}

	return false
}

// hasDirectQUICConn returns true if there's already a direct QUIC connection among the given conns.
func hasDirectQUICConn(conns []network.Conn) bool {
	for _, conn := range conns {
		if isQUICAddr(conn.RemoteMultiaddr()) && !isRelayAddr(conn.RemoteMultiaddr()) {
			return true
		}
	}

	return false
}

// isProtocolAddr return true if the multiaddr has protocol code p
func isProtocolAddr(a ma.Multiaddr, p int) bool {
	found := false

	ma.ForEach(a, func(c ma.Component) bool {
		if c.Protocol().Code == p {
			found = true
			return false
		}

		return true
	})

	return found
}

// isTCPAddr returns true if the multiaddr is TCP
func isTCPAddr(a ma.Multiaddr) bool {
	return isProtocolAddr(a, ma.P_TCP)
}

// isQUICAddr returns true if the multiaddr is QUIC
func isQUICAddr(a ma.Multiaddr) bool {
	return isProtocolAddr(a, ma.P_QUIC) || isProtocolAddr(a, ma.P_QUIC_V1)
}

// isRelayAddr returns true if the multiaddr is p2p-circuit
func isRelayAddr(addr ma.Multiaddr) bool {
	return isProtocolAddr(addr, ma.P_CIRCUIT)
}

// RegisterConnectionLogger registers a connection logger with the host.
// This is pretty weird and hacky, but that is because libp2p uses the network.Notifiee interface as a map key,
// so the implementation can only contain fields that are hashable. So we use a channel and do the logic externally. :(.
func RegisterConnectionLogger(ctx context.Context, p2pNode host.Host, peerIDs []peer.ID) {
	ctx = log.WithTopic(ctx, "p2p")

	type connKey struct {
		PeerID   peer.ID
		Type     string
		Protocol string
	}

	type streamKey struct {
		PeerName  string
		Direction string
		Protocol  string
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

	p2pNode.Network().Notify(connLogger{
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
				// Instrument connection and stream counts.
				counts := make(map[connKey]int)
				streams := make(map[streamKey]int)

				for _, conn := range p2pNode.Network().Conns() {
					cKey := connKey{
						PeerID:   conn.RemotePeer(),
						Type:     addrType(conn.RemoteMultiaddr()),
						Protocol: addrProtocol(conn.RemoteMultiaddr()),
					}
					counts[cKey]++

					for _, stream := range conn.GetStreams() {
						sKey := streamKey{
							PeerName:  PeerName(conn.RemotePeer()),
							Direction: stream.Stat().Direction.String(),
							Protocol:  string(stream.Protocol()),
						}
						streams[sKey]++
					}
				}

				peerStreamGauge.Reset() // Reset stream gauge to clear previously set protocols.

				existing := make(map[string]bool)

				for cKey, count := range counts {
					peerName := PeerName(cKey.PeerID)
					if slices.Contains(peerIDs, cKey.PeerID) {
						peerConnTypeGauge.WithLabelValues(peerName, cKey.Type, cKey.Protocol).Set(float64(count))
					} else {
						relayConnTypeGauge.WithLabelValues(peerName, cKey.Type, cKey.Protocol).Set(float64(count))
					}
					existing[peerName+":"+cKey.Type] = true
				}

				// Ensure zero values for peer/type combinations that have no connections
				for _, pID := range peerIDs {
					peerName := PeerName(pID)
					for _, typ := range []string{addrTypeRelay, addrTypeDirect} {
						if !existing[peerName+":"+typ] {
							peerConnTypeGauge.WithLabelValues(peerName, typ, protocolNone).Set(0)
						}
					}
				}

				for sKey, amount := range streams {
					peerStreamGauge.WithLabelValues(sKey.PeerName, sKey.Direction, sKey.Protocol).Set(float64(amount))
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

// addrProtocol returns the transport protocol name from a multiaddr
func addrProtocol(addr ma.Multiaddr) string {
	if isQUICAddr(addr) {
		return protocolQUIC
	}

	if isTCPAddr(addr) {
		return protocolTCP
	}

	return protocolUnknown
}

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
