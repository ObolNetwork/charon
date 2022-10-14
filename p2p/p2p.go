// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package p2p

import (
	"context"
	"crypto/ecdsa"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/libp2p/go-libp2p"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/routing"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/lifecycle"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/app/z"
)

// NewTCPNode returns a started tcp-based libp2p host.
func NewTCPNode(ctx context.Context, cfg Config, key *ecdsa.PrivateKey, connGater ConnGater, opts ...libp2p.Option,
) (host.Host, error) {
	addrs, err := cfg.Multiaddrs()
	if err != nil {
		return nil, err
	}

	if len(addrs) == 0 {
		log.Info(ctx, "LibP2P not accepting incoming connections since --p2p-tcp-addresses empty")
	}

	priv, err := libp2pcrypto.UnmarshalSecp256k1PrivateKey(crypto.FromECDSA(key))
	if err != nil {
		return nil, errors.Wrap(err, "convert privkey")
	}

	// Init options.
	defaultOpts := []libp2p.Option{
		// Set P2P identity key.
		libp2p.Identity(priv),
		// Set TCP listen addresses.
		libp2p.ListenAddrs(addrs...),
		// Set up user-agent.
		libp2p.UserAgent("obolnetwork-charon/" + version.Version),
		// Limit connections to DV peers.
		libp2p.ConnectionGater(connGater),
		// Enable Autonat (required for hole punching)
		libp2p.EnableNATService(),
		// Define p2pcfg.AddrsFactory that does not advertise
		// addresses via libp2p, since we use discv5 for peer discovery.
		libp2p.AddrsFactory(func([]ma.Multiaddr) []ma.Multiaddr { return nil }),
	}

	defaultOpts = append(defaultOpts, opts...)

	tcpNode, err := libp2p.New(defaultOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "new libp2p node")
	}

	return tcpNode, nil
}

// multiAddrViaRelay returns a multiaddr to the peer via the relay.
// See https://github.com/libp2p/go-libp2p/blob/master/examples/relay/main.go.
func multiAddrViaRelay(relayPeer Peer, peerID peer.ID) (ma.Multiaddr, error) {
	transportAddr, err := multiAddrFromIPPort(relayPeer.Enode.IP(), relayPeer.Enode.TCP())
	if err != nil {
		return nil, err
	}

	addr := fmt.Sprintf("/p2p/%s/p2p-circuit/p2p/%s", relayPeer.ID.Pretty(), peerID.Pretty())
	relayAddr, err := ma.NewMultiaddr(addr)
	if err != nil {
		return nil, errors.Wrap(err, "new multiaddr")
	}

	return transportAddr.Encapsulate(relayAddr), nil
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
					log.Info(ctx, "Libp2p reachablity changed", z.Any("status", evt.Reachability))
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

// RegisterConnectionLogger registers a connection logger with the host.
// This is pretty weird and hacky, but that is because libp2p uses the network.Notifiee interface as a map key,
// so the implementation can only contain fields that are hashable. So we use a channel and do the logic externally. :(.
func RegisterConnectionLogger(tcpNode host.Host, peerIDs []peer.ID) {
	var (
		peers  = make(map[peer.ID]bool)
		events = make(chan logEvent)
	)

	for _, p := range peerIDs {
		peers[p] = true
	}

	tcpNode.Network().Notify(connLogger{
		events: events,
	})

	go func() {
		ctx := log.WithTopic(context.Background(), "p2p")
		for e := range events {
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
			}

			if !peers[e.Peer] {
				// Do not instrument relays.
				continue
			}

			if e.Connected {
				peerConnGauge.WithLabelValues(name, addrType(e.Addr)).Inc()
			} else if e.Disconnect {
				peerConnGauge.WithLabelValues(name, addrType(e.Addr)).Dec()
			}

			// Ensure both connection type metrics are initiated
			peerConnGauge.WithLabelValues(name, addrTypeDirect).Add(0)
			peerConnGauge.WithLabelValues(name, addrTypeRelay).Add(0)
		}
	}()
}

type logEvent struct {
	Peer       peer.ID
	Addr       ma.Multiaddr
	Direction  network.Direction
	Connected  bool
	Disconnect bool
	Listen     bool
}

// connLogger implements network.Notifee and only sends logEvents on a channel since
// it is used as a map key internally in libp2p, it cannot contain complex types.
type connLogger struct {
	events chan logEvent
}

func (l connLogger) Listen(_ network.Network, addr ma.Multiaddr) {
	l.events <- logEvent{
		Addr:   addr,
		Listen: true,
	}
}

func (connLogger) ListenClose(network.Network, ma.Multiaddr) {}

func (l connLogger) Connected(_ network.Network, conn network.Conn) {
	l.events <- logEvent{
		Peer:      conn.RemotePeer(),
		Addr:      conn.RemoteMultiaddr(),
		Direction: conn.Stat().Direction,
		Connected: true,
	}
}

func (l connLogger) Disconnected(_ network.Network, conn network.Conn) {
	l.events <- logEvent{
		Peer:       conn.RemotePeer(),
		Addr:       conn.RemoteMultiaddr(),
		Disconnect: true,
	}
}

var (
	_ routing.PeerRouting = peerRoutingFunc(nil) // interface assertion
	_ network.Notifiee    = connLogger{}
)

// addrType returns 'direct' or 'relay' based on whether the address contains a relay.
func addrType(a ma.Multiaddr) string {
	if isRelayAddr(a) {
		return addrTypeRelay
	}

	return addrTypeDirect
}

// isRelayAddr returns true if the address is a relayed address.
// Copied from github.com/libp2p/go-libp2p@v0.22.0/p2p/protocol/circuitv2/relay/relay.go:593.
func isRelayAddr(a ma.Multiaddr) bool {
	_, err := a.ValueForProtocol(ma.P_CIRCUIT)
	return err == nil
}
