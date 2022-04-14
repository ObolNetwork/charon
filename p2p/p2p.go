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

	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/routing"
	noise "github.com/libp2p/go-libp2p-noise"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/app/z"
)

// NewTCPNode returns a started tcp-based libp2p node.
func NewTCPNode(cfg Config, key *ecdsa.PrivateKey, connGater ConnGater,
	udpNode UDPNode, peers []Peer) (host.Host, error,
) {
	addrs, err := cfg.Multiaddrs()
	if err != nil {
		return nil, err
	}

	// Init options.
	opts := []libp2p.Option{
		// Set P2P identity key.
		libp2p.Identity(crypto.PrivKey((*crypto.Secp256k1PrivateKey)(key))),
		// Set noise-libp2p handshake.
		libp2p.Security(noise.ID, noise.New),
		// Set listen addresses.
		libp2p.ListenAddrs(addrs...),
		// Set up user-agent.
		libp2p.UserAgent("obolnetwork-charon/" + version.Version),
		// Limit connections to DV peers.
		libp2p.ConnectionGater(connGater),

		libp2p.Routing(func(h host.Host) (routing.PeerRouting, error) {
			return logWrapRouting(adaptDiscRouting(udpNode, peers)), nil
		}),
	}

	tcpNode, err := libp2p.New(opts...)
	if err != nil {
		return nil, errors.Wrap(err, "new libp2p node")
	}

	return tcpNode, nil
}

// logWrapRouting wraps a peerRoutingFunc in debug logging.
func logWrapRouting(fn peerRoutingFunc) peerRoutingFunc {
	var failing sync.Map // map[peer.ID]struct{}
	return func(ctx context.Context, p peer.ID) (peer.AddrInfo, error) {
		ctx = log.WithTopic(ctx, "p2p")

		res, err := fn(ctx, p)
		if err != nil {
			if _, ok := failing.Load(p); !ok {
				log.Debug(ctx, "Peer routing request failure",
					z.Any("error", err), z.Str("peer", ShortID(p)))
			}
			failing.Store(p, struct{}{})
		} else {
			log.Debug(ctx, "Peer routing request success",
				z.Any("addrs", res.Addrs), z.Str("peer", ShortID(p)))
			failing.Delete(p)
		}

		return res, err
	}
}

// adaptDiscRouting returns a function that adapts p2p routing requests to discv5 lookups.
func adaptDiscRouting(udpNode UDPNode, peers []Peer) peerRoutingFunc {
	peerMap := make(map[peer.ID]enode.Node)
	for _, p := range peers {
		peerMap[p.ID] = p.Enode
	}

	for _, bootnode := range udpNode.Relays {
		peerMap[bootnode.ID] = bootnode.Enode
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
		for _, relay := range udpNode.Relays {
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

// peerRoutingFunc wraps a function to implement routing.PeerRouting.
type peerRoutingFunc func(context.Context, peer.ID) (peer.AddrInfo, error)

func (f peerRoutingFunc) FindPeer(ctx context.Context, p peer.ID) (peer.AddrInfo, error) {
	return f(ctx, p)
}

var _ routing.PeerRouting = peerRoutingFunc(nil) // interface assertion
