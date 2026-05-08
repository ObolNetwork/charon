// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
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
func NewRelayReserver(p2pNode host.Host, relay *MutablePeer) lifecycle.HookFuncCtx {
	return func(ctx context.Context) {
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

			resv, err := circuit.Reserve(ctx, p2pNode, relayPeer.AddrInfo())
			if err != nil {
				log.Warn(ctx, "Reserve relay circuit", err, z.Str("relay_peer", name))
				backoff()

				continue
			}

			resetBackoff()

			// Note a single long-lived reservation (created by server-side) is mapped to
			// many short-lived limited client-side connections.
			// When the reservation expires, the server needs to re-reserve.
			// When the server isn't connected to the relay anymore, it needs to reconnect/re-reserve.
			// When the client connection expires (stream reset error), then client needs to reconnect.

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

			checkConnTicker := time.NewTicker(time.Millisecond * 500)

			for {
				select {
				case <-checkConnTicker.C:
					if len(p2pNode.Network().ConnsToPeer(relayPeer.ID)) > 0 {
						continue // Still connected, continue for loop
					}

					log.Debug(ctx, "No relay connection, reconnecting",
						z.Str("relay_peer", name))
					// Break out of for loop below to reconnect/re-reserve
				case <-refresh:
					// Break out of for loop below to reconnect/re-reserve
				case <-ctx.Done():
					// Break out of for loop below to return after stopping ticker
				}

				break
			}

			checkConnTicker.Stop()

			if ctx.Err() != nil {
				return
			}

			log.Debug(ctx, "Refreshing relay circuit reservation")
			relayConnGauge.WithLabelValues(name).Set(0)
		}
	}
}

// NewRelayRouter returns a life cycle hook that routes peers via relays in libp2p by
// continuously adding peer relay addresses to libp2p peer store.
//
// Only relay routes for peers that THIS node should dial are added. For each
// peer pair, the node with the smaller peer ID dials and the node with the
// larger peer ID waits. This asymmetry is required for DCUtR (hole punching)
// to work: libp2p's holepunch service only initiates the DCUtR protocol on
// INBOUND relay connections. If both sides add relay routes and dial
// simultaneously, both see outbound connections and neither side triggers
// DCUtR. By having one side wait, it sees the other's dial as an inbound
// relay connection, which activates DCUtR and enables NAT traversal.
func NewRelayRouter(p2pNode host.Host, peers []peer.ID, relays []*MutablePeer) lifecycle.HookFuncCtx {
	return func(ctx context.Context) {
		if len(relays) == 0 {
			return
		}

		ctx = log.WithTopic(ctx, "p2p")

		selfID := p2pNode.ID()

		for _, pID := range peers {
			if pID == selfID {
				continue
			}

			if shouldDialPeer(selfID, pID) {
				log.Debug(ctx, "Will dial peer via relay (our ID < peer ID)",
					z.Str("peer", PeerName(pID)),
					z.Str("self_id", selfID.String()),
					z.Str("peer_id", pID.String()),
				)
			} else {
				log.Debug(ctx, "Will wait for inbound relay connection from peer (our ID > peer ID), expecting DCUtR hole punch",
					z.Str("peer", PeerName(pID)),
					z.Str("self_id", selfID.String()),
					z.Str("peer_id", pID.String()),
				)
			}
		}

		ticker := time.NewTicker(routedAddrTTL * 9 / 10)
		defer ticker.Stop()

		for {
			for _, pID := range peers {
				if pID == selfID {
					continue
				}

				if !shouldDialPeer(selfID, pID) {
					continue
				}

				for _, mutable := range relays {
					relay, ok := mutable.Peer()
					if !ok {
						continue
					}

					relayAddrs, err := multiAddrsViaRelay(relay, pID)
					if err != nil {
						log.Error(ctx, "Failed to create multi-address for peer via relay", err)
						continue
					}

					p2pNode.Peerstore().AddAddrs(pID, relayAddrs, routedAddrTTL)
				}
			}

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}
}

// shouldDialPeer returns true if this node should proactively dial the given
// peer via relay. The peer with the smaller ID dials; the peer with the larger
// ID waits for the inbound connection (which triggers DCUtR hole punching).
func shouldDialPeer(self, remote peer.ID) bool {
	return self < remote
}
