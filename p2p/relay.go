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

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peerstore"
	circuit "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"

	"github.com/obolnetwork/charon/app/expbackoff"
	"github.com/obolnetwork/charon/app/lifecycle"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

// routedAddrTTL is a peer store TTL used to notify libp2p of peer addresses.
// We use a custom TTL (different from well-known peer store TTLs) since
// this mitigates against other libp2p services (like Identify) modifying
// or removing them.
var routedAddrTTL = peerstore.TempAddrTTL + 1

// NewRelayReserver returns a life cycle hook function that continuously
// reserves a relay circuit until the context is closed.
func NewRelayReserver(tcpNode host.Host, relay *MutablePeer) lifecycle.HookFunc {
	return func(ctx context.Context) error {
		ctx = log.WithTopic(ctx, "relay")
		backoff, resetBackoff := expbackoff.NewWithReset(ctx)

		for ctx.Err() == nil {
			relayPeer, ok := relay.Peer()
			if !ok {
				time.Sleep(time.Second * 10) // Constant 10s backoff ok for mutexed lookups
				continue
			}

			name := PeerName(relayPeer.ID)

			relayConnGauge.WithLabelValues(name).Set(0)

			resv, err := circuit.Reserve(ctx, tcpNode, relayPeer.AddrInfo())
			if err != nil {
				log.Warn(ctx, "Reserve relay circuit", err, z.Str("relay_peer", name))
				backoff()

				continue
			}
			resetBackoff()

			// Note a single long-lived reservation (created by server-side) is mapped to
			// many short-lived limited client-side connections.
			// When the reservation expires, the server needs to re-reserve.
			// When the connection expires (stream reset error), then client needs to reconnect.

			refreshDelay := time.Until(resv.Expiration.Add(-2 * time.Minute))

			log.Debug(ctx, "Relay circuit reserved",
				z.Any("reservation_expire", resv.Expiration),        // Server side reservation expiry (long)
				z.Any("connection_duration", resv.LimitDuration),    // Client side connection limit (short)
				z.Any("connection_data_mb", resv.LimitData/(1<<20)), // Client side connection limit (short)
				z.Any("refresh_delay", refreshDelay),
				z.Str("relay_peer", name),
			)
			relayConnGauge.WithLabelValues(name).Set(1)

			refresh := time.After(refreshDelay)

			var done bool
			for !done {
				select {
				case <-ctx.Done():
					done = true
				case <-refresh:
					done = true
				}
			}

			log.Debug(ctx, "Refreshing relay circuit reservation")
		}

		return nil
	}
}

// NewRelayRouter returns a life cycle hook that routes peers via relays in libp2p by
// continuously adding peer relay addresses to libp2p peer store.
func NewRelayRouter(tcpNode host.Host, peers []Peer, relays []*MutablePeer) lifecycle.HookFuncCtx {
	return func(ctx context.Context) {
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

				for _, mutable := range relays {
					relay, ok := mutable.Peer()
					if !ok {
						continue
					}

					relayAddrs, err := multiAddrsViaRelay(relay, p.ID)
					if err != nil {
						log.Error(ctx, "Failed discovering peer address", err)
						continue
					}

					tcpNode.Peerstore().AddAddrs(p.ID, relayAddrs, routedAddrTTL)
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
