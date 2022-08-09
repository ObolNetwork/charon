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
	"sync"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/libp2p/go-libp2p"
	libp2pcrypto "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/event"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/routing"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/lifecycle"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/app/z"
)

// NewTCPNode returns a started tcp-based libp2p host.
func NewTCPNode(cfg Config, key *ecdsa.PrivateKey, connGater ConnGater,
	udpNode *discover.UDPv5, peers, relays []Peer) (host.Host, error,
) {
	addrs, err := cfg.Multiaddrs()
	if err != nil {
		return nil, err
	}

	priv, err := libp2pcrypto.UnmarshalSecp256k1PrivateKey(crypto.FromECDSA(key))
	if err != nil {
		return nil, errors.Wrap(err, "convert privkey")
	}

	// Init options.
	opts := []libp2p.Option{
		// Set P2P identity key.
		libp2p.Identity(priv),
		// Set listen addresses.
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

		libp2p.Routing(func(h host.Host) (routing.PeerRouting, error) {
			return logWrapRouting(adaptDiscRouting(udpNode, peers, relays)), nil
		}),
	}

	tcpNode, err := libp2p.New(opts...)
	if err != nil {
		return nil, errors.Wrap(err, "new libp2p node")
	}

	// Register debug logger.
	tcpNode.Network().Notify(debugLogger{ctx: log.WithTopic(context.Background(), "p2p")})

	return tcpNode, nil
}

// logWrapRouting wraps a peerRoutingFunc in debug logging.
func logWrapRouting(fn peerRoutingFunc) peerRoutingFunc {
	var failing sync.Map // map[peer.syncProtoID]struct{}
	return func(ctx context.Context, p peer.ID) (peer.AddrInfo, error) {
		ctx = log.WithTopic(ctx, "p2p")

		res, err := fn(ctx, p)
		if err != nil {
			if _, ok := failing.Load(p); !ok {
				log.Debug(ctx, "Peer routing request failure",
					z.Any("error", err), z.Str("peer", PeerName(p)))
			}
			failing.Store(p, struct{}{})
		} else {
			log.Debug(ctx, "Peer routing request success",
				z.Any("addrs", res.Addrs), z.Str("peer", PeerName(p)))
			failing.Delete(p)
		}

		return res, err
	}
}

// adaptDiscRouting returns a function that adapts p2p routing requests to discv5 lookups.
func adaptDiscRouting(udpNode *discover.UDPv5, peers, relays []Peer) peerRoutingFunc {
	peerMap := make(map[peer.ID]enode.Node)
	for _, p := range peers {
		peerMap[p.ID] = p.Enode
	}

	for _, relay := range relays {
		peerMap[relay.ID] = relay.Enode
	}

	return func(ctx context.Context, peerID peer.ID) (peer.AddrInfo, error) {
		node, ok := peerMap[peerID]
		if !ok {
			return peer.AddrInfo{}, errors.New("unknown peer")
		}

		resolved := udpNode.Resolve(&node)
		if resolved == nil {
			return peer.AddrInfo{}, errors.New("peer not resolved")
		}

		var mAddrs []ma.Multiaddr

		// If sequence is 0, we haven't discovered it yet.
		// If tcp port is 0, this node isn't bound to a port.
		if resolved.Seq() != 0 && resolved.TCP() != 0 {
			mAddr, err := multiAddrFromIPPort(resolved.IP(), resolved.TCP())
			if err != nil {
				return peer.AddrInfo{}, err
			}
			mAddrs = append(mAddrs, mAddr)
		}

		// Add any circuit relays
		for _, relay := range relays {
			if relay.Enode.TCP() == 0 {
				continue
			}

			relayAddr, err := multiAddrViaRelay(relay, peerID)
			if err != nil {
				return peer.AddrInfo{}, err
			}
			mAddrs = append(mAddrs, relayAddr)
		}

		if len(mAddrs) == 0 {
			return peer.AddrInfo{}, errors.New("peer not accessible")
		}

		return peer.AddrInfo{
			ID:    peerID,
			Addrs: mAddrs,
		}, nil
	}
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

// debugLogger implements network.Notifee and does debug logging.
type debugLogger struct {
	ctx context.Context
}

func (n debugLogger) Listen(_ network.Network, addr ma.Multiaddr) {
	log.Debug(n.ctx, "Libp2p listening on address", z.Any("address", addr.String()))
}

func (debugLogger) ListenClose(network.Network, ma.Multiaddr) {}

func (n debugLogger) Connected(_ network.Network, conn network.Conn) {
	log.Debug(n.ctx, "Libp2p new connection",
		z.Str("peer", PeerName(conn.RemotePeer())),
		z.Any("peer_address", conn.RemoteMultiaddr()),
		z.Any("direction", conn.Stat().Direction),
	)
}

func (debugLogger) Disconnected(network.Network, network.Conn) {}

var (
	_ routing.PeerRouting = peerRoutingFunc(nil) // interface assertion
	_ network.Notifiee    = debugLogger{}
)
