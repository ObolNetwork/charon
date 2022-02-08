// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package p2p

import (
	"context"
	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum/p2p/discover"
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
	discNode *discover.UDPv5) (host.Host, error) {

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
		libp2p.UserAgent("ObolNetwork-Charon/" + version.Version),
		// Limit connections to DV peers.
		libp2p.ConnectionGater(connGater),

		libp2p.Routing(func(h host.Host) (routing.PeerRouting, error) {
			return logWrapRouting(adaptDiscRouting(discNode)), nil
		}),
	}

	return libp2p.New(opts...)
}

// logWrapRouting wraps a peerRoutingFunc in debug logging.
func logWrapRouting(fn peerRoutingFunc) peerRoutingFunc {
	return func(ctx context.Context, p peer.ID) (peer.AddrInfo, error) {
		ctx = log.WithTopic(ctx, "p2p")

		res, err := fn(ctx, p)
		if err != nil {
			log.Debug(ctx, "Peer routing request failure",
				z.Any("error", err), z.Str("peer", ShortID(p)))
		} else {
			log.Debug(ctx, "Peer routing request success",
				z.Any("addrs", res.Addrs), z.Str("peer", ShortID(p)))
		}

		return res, err
	}
}

// adaptDiscRouting returns a function that adapts p2p routing requests to discv5 lookups.
func adaptDiscRouting(disc *discover.UDPv5) peerRoutingFunc {
	return func(ctx context.Context, p peer.ID) (peer.AddrInfo, error) {
		cPubkey, err := p.ExtractPublicKey()
		if err != nil {
			return peer.AddrInfo{}, err
		}

		sPubkey, ok := cPubkey.(*crypto.Secp256k1PublicKey)
		if !ok {
			return peer.AddrInfo{}, errors.New("invalid peer pubkey")
		}

		ePubkey := ecdsa.PublicKey(*sPubkey)

		targets := disc.Lookup(enode.PubkeyToIDV4(&ePubkey))

		if len(targets) == 0 {
			return peer.AddrInfo{}, errors.New("discv5 peer not found")
		}

		mAddr, err := multiAddrFromIPPort(targets[0].IP(), targets[0].TCP())
		if err != nil {
			return peer.AddrInfo{}, err
		}

		return peer.AddrInfo{
			ID:    p,
			Addrs: []ma.Multiaddr{mAddr},
		}, nil
	}
}

// peerRoutingFunc wraps a function to implement routing.PeerRouting.
type peerRoutingFunc func(context.Context, peer.ID) (peer.AddrInfo, error)

func (f peerRoutingFunc) FindPeer(ctx context.Context, p peer.ID) (peer.AddrInfo, error) {
	return f(ctx, p)
}

var _ routing.PeerRouting = peerRoutingFunc(nil) // interface assertion
