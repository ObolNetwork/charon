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
	"time"

	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/peerstore"
	circuit "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/app/lifecycle"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

// routedAddrTTL is a peer store TTL used to notify libp2p of peer addresses.
// We use a custom TTL (different from well-known peer store TTLs) since
// this mitigates against other libp2p services (like Identify) modifying
// or removing them.
var routedAddrTTL = peerstore.TempAddrTTL + 1

// NewRelays returns the libp2p circuit relays from bootnodes if enabled.
func NewRelays(conf Config, bootnodes []*enode.Node) ([]Peer, error) {
	if !conf.BootnodeRelay {
		return nil, nil
	} else if conf.UDPBootLock {
		// Relays not supported via manifest bootnodes yet.
		return nil, nil
	}

	var resp []Peer
	for _, bootnode := range bootnodes {
		record := bootnode.Record()
		p, err := NewPeer(*record, -1)
		if err != nil {
			return nil, err
		}
		resp = append(resp, p)
	}

	return resp, nil
}

// NewRelayReserver returns a life cycle hook function that continuously
// reserves a relay circuit until the context is closed.
func NewRelayReserver(tcpNode host.Host, relay Peer) lifecycle.HookFunc {
	return func(ctx context.Context) error {
		ctx = log.WithTopic(ctx, "relay")
		name := PeerName(relay.ID)
		ctx = log.WithCtx(ctx, z.Str("relay_peer", name))

		if relay.Enode.TCP() == 0 {
			log.Debug(ctx, "Relay not accessible")
			return nil
		}

		bootAddr, err := multiAddrFromIPPort(relay.Enode.IP(), relay.Enode.TCP())
		if err != nil {
			return errors.Wrap(err, "relay address")
		}

		addrInfo := peer.AddrInfo{
			ID:    relay.ID,
			Addrs: []ma.Multiaddr{bootAddr},
		}

		for ctx.Err() == nil {
			relayConnGauge.WithLabelValues(name).Set(0)

			resv, err := circuit.Reserve(ctx, tcpNode, addrInfo)
			if err != nil {
				log.Warn(ctx, "Reserve relay circuit", err)
				time.Sleep(time.Second * 5) // TODO(corver): Improve backoff

				continue
			}

			// Note a single long-lived reservation (created by server-side) is mapped to
			// many short-lived limited client-side connections.
			// When the reservation expires, the server needs to re-reserve.
			// When the connection expires (stream reset error), then client needs to reconnect.

			log.Debug(ctx, "Relay circuit reserved",
				z.Any("reservation_expire", resv.Expiration),        // Server side reservation expiry (long)
				z.Any("connection_duration", resv.LimitDuration),    // Client side connection limit (short)
				z.Any("connection_data_mb", resv.LimitData/(1<<20)), // Client side connection limit (short)
			)
			relayConnGauge.WithLabelValues(name).Set(1)

			ticker := time.NewTicker(time.Second * 5)

			for ok := true; ok; {
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(time.Until(resv.Expiration.Add(-time.Minute))):
					ok = false
				case <-ticker.C:
					if len(tcpNode.Network().ConnsToPeer(relay.ID)) == 0 {
						log.Warn(ctx, "No connections to relay", nil)
						ok = false
					}
				}
			}

			log.Debug(ctx, "Refreshing relay circuit reservation")
		}

		return nil
	}
}

// NewRelayRouter returns a life cycle hook that routes peers via relays in libp2p by
// continuously adding peer relay addresses to libp2p peer store.
func NewRelayRouter(tcpNode host.Host, peers []Peer, relays []Peer) lifecycle.HookFuncCtx {
	return func(ctx context.Context) {
		if !featureset.Enabled(featureset.InvertLibP2PRouting) {
			return
		}
		if len(relays) == 0 {
			return
		}

		ctx = log.WithTopic(ctx, "p2p")

		for ctx.Err() == nil {
			for _, p := range peers {
				if p.ID == tcpNode.ID() {
					// Skip self
					continue
				}

				for _, relay := range relays {
					if relay.Enode.TCP() == 0 {
						continue
					}

					relayAddr, err := multiAddrViaRelay(relay, p.ID)
					if err != nil {
						log.Error(ctx, "Failed discovering peer address", err)
						continue
					}

					tcpNode.Peerstore().AddAddr(p.ID, relayAddr, routedAddrTTL)
				}
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(routedAddrTTL * 9 / 10):
			}
		}
	}
}
