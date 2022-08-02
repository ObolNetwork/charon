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
	p2plogging "github.com/ipfs/go-log/v2"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/libp2p/go-libp2p"
	libp2pcrypto "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/peerstore"
	"github.com/libp2p/go-libp2p-core/routing"
	p2pconfig "github.com/libp2p/go-libp2p/config"
	"github.com/libp2p/go-libp2p/p2p/protocol/holepunch"
	"github.com/libp2p/go-libp2p/p2p/protocol/identify"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/featureset"
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
		// Advertise public addresses for hole punching.
		libp2p.AddrsFactory(advertisePublicAddrs()),
		// Query discv5 when no address for peer is known.
		libp2p.Routing(func(h host.Host) (routing.PeerRouting, error) {
			return logWrapRouting(adaptDiscRouting(udpNode, peers, relays)), nil
		}),
	}

	// Override defaults for snappy re-resolving of addresses.
	if featureset.Enabled(featureset.HolePunch) {
		// Decrease not-currently-connected address TTL to absolute minimum, since
		// observed public NAT addresses are linked to relay connections that recycle
		// every two minutes. Rather re-establish relay connection and upgrade that again.

		peerstore.TempAddrTTL = time.Second * 1              // Default is 2 min
		peerstore.RecentlyConnectedAddrTTL = time.Second * 1 // Default is 30 min
		peerstore.OwnObservedAddrTTL = time.Minute           // Default is 30 min

		// Only require a single peer (single bootnode) to report our public IP (default is 4).
		identify.ActivationThresh = 1

		opts = append(opts, libp2p.EnableHolePunching(holepunch.WithTracer(holePunchLogger{})))

		// TODO(corver): Remove debug logging when hole punch moves to beta.
		for _, module := range []string{"autonat", "p2p-holepunch"} {
			if err = p2plogging.SetLogLevel(module, "debug"); err != nil {
				return nil, errors.Wrap(err, "set log level", z.Str("module", module))
			}
		}
	}

	tcpNode, err := libp2p.New(opts...)
	if err != nil {
		return nil, errors.Wrap(err, "new libp2p node")
	}

	return tcpNode, nil
}

// NewConnectionLogger returns a lifecycle function to continuously log peer connections.
func NewConnectionLogger(tcpNode host.Host, peers []peer.ID) func(context.Context) error {
	return func(ctx context.Context) error {
		ctx = log.WithTopic(ctx, "p2p")
		for {
			time.Sleep(time.Second * 10)
			for _, pID := range peers {
				if pID == tcpNode.ID() {
					continue
				}

				for i, conn := range tcpNode.Network().ConnsToPeer(pID) {
					typ := "direct"
					if _, err := conn.RemoteMultiaddr().ValueForProtocol(ma.P_CIRCUIT); err == nil {
						typ = "relay"
					}
					stat := conn.Stat()
					log.Debug(ctx, "Peer connection stats",
						z.Str("peer", PeerName(pID)),
						z.Int("index", i),
						z.Bool("transient", stat.Transient),
						z.Str("type", typ),
						z.Any("duration", time.Since(stat.Opened).Truncate(time.Second)),
						z.Any("direction", stat.Direction),
					)
				}
			}
		}
	}
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
			_, err := multiAddrFromIPPort(resolved.IP(), resolved.TCP())
			if err != nil {
				return peer.AddrInfo{}, err
			}
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

// advertisePublicAddrs returns a libp2p advertised address transformation function
// that only advertises public addresses (required for hole punching)
//
// Private addresses are filtered out since they tend to clog up the peer store with
// unreachable private addresses that need to timeout before they are removed
// increasing latency for re-establishing connection.
//
// Note that this means hole punching and other advanced features of libp2p requiring
// advertised addressed will not work on private networks, but this is ok for now since private
// networks can probably configure direct access via ENRs.
func advertisePublicAddrs() p2pconfig.AddrsFactory {
	return func(addrs []ma.Multiaddr) []ma.Multiaddr {
		var resp []ma.Multiaddr
		for _, addr := range addrs {
			if manet.IsPublicAddr(addr) {
				resp = append(resp, addr)
			}
		}

		return resp
	}
}

// peerRoutingFunc wraps a function to implement routing.PeerRouting.
type peerRoutingFunc func(context.Context, peer.ID) (peer.AddrInfo, error)

func (f peerRoutingFunc) FindPeer(ctx context.Context, p peer.ID) (peer.AddrInfo, error) {
	return f(ctx, p)
}

var _ routing.PeerRouting = peerRoutingFunc(nil) // interface assertion

type holePunchLogger struct{}

func (holePunchLogger) Trace(e *holepunch.Event) {
	ctx := log.WithTopic(context.Background(), "holepunch")
	log.Debug(ctx, "Libp2p holepunch event",
		z.Str("event", e.Type),
		z.Str("peer", PeerName(e.Remote)))
}
