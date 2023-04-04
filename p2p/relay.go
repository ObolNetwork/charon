// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	circuit "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
	"github.com/multiformats/go-multistream"

	"github.com/obolnetwork/charon/app/errors"
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
func NewRelayReserver(tcpNode host.Host, relay *MutablePeer, pingSvc *ping.PingService) lifecycle.HookFuncCtx {
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

			resv, err := circuit.Reserve(ctx, tcpNode, relayPeer.AddrInfo())
			if err != nil {
				log.Warn(ctx, "Reserve relay circuit", err, z.Str("relay_peer", name))
				backoff()

				continue
			}

			relayConnGauge.WithLabelValues(name).Set(1)
			resetBackoff()

			// Note a single long-lived reservation (created by server-side) is mapped to
			// many short-lived limited client-side connections.
			// When the reservation expires, the server needs to re-reserve.
			// When the server isn't connected to the relay anymore, it needs to reconnect/re-reserve.
			// When the client connection expires (stream reset error), then client needs to reconnect.

			refreshDelay := time.Until(resv.Expiration.Add(-2 * time.Minute))
			refresh := time.After(refreshDelay)

			log.Debug(ctx, "Relay circuit reserved",
				z.Any("reservation_expire", resv.Expiration),        // Server side reservation expiry (long)
				z.Any("connection_duration", resv.LimitDuration),    // Client side connection limit (short)
				z.Any("connection_data_mb", resv.LimitData/(1<<20)), // Client side connection limit (short)
				z.Any("refresh_delay", refreshDelay),
				z.Str("relay_peer", name),
			)

			connCheckTicker := time.NewTicker(time.Millisecond * 100) // In memory check frequently
			pingCheckTicker := time.NewTicker(time.Second)            // Network check less frequently
			pingResults := pingSvc.Ping(ctx, relayPeer.ID)

			for {
				select {
				case <-pingCheckTicker.C:
					if checkPingResult(ctx, pingResults, pingCheckTicker, name) {
						continue // Ping ok, still connected, continue for-loop
					}
					// Break out of for-loop below to reconnect/re-reserve
				case <-connCheckTicker.C:
					if len(tcpNode.Network().ConnsToPeer(relayPeer.ID)) > 0 {
						continue // Still connected, continue for-loop
					}
					log.Debug(ctx, "No relay connection, reconnecting",
						z.Str("relay_peer", name))
					// Break out of for-loop below to reconnect/re-reserve
				case <-refresh:
					// Break out of for-loop below to reconnect/re-reserve
				case <-ctx.Done():
					// Break out of for-loop below to reconnect/re-reserve
				}

				break
			}

			connCheckTicker.Stop()
			pingCheckTicker.Stop()

			if ctx.Err() != nil {
				return
			}

			log.Debug(ctx, "Refreshing relay circuit reservation")
			relayConnGauge.WithLabelValues(name).Set(0)
		}
	}
}

// checkPingResult returns true if the ping was ok, false if it failed.
func checkPingResult(ctx context.Context, pingResult <-chan ping.Result, pingCheckTimer *time.Ticker, name string) bool {
	select {
	case result := <-pingResult:
		if errors.Is(result.Error, context.Canceled) {
			return false
		} else if isErrProtocolNotSupported(result.Error) {
			log.Warn(ctx, "Relay doesn't support ping protocol", result.Error, z.Str("relay_peer", name))
			pingCheckTimer.Stop() // Stop checking ping results.

			return true
		} else if result.Error != nil {
			log.Warn(ctx, "Relay ping failed, reconnecting", result.Error, z.Str("relay_peer", name))
			return false
		} else {
			log.Debug(ctx, "Relay ping successful", z.Str("relay_peer", name), z.Any("rtt", result.RTT))
			return true
		}
	default:
		return true // No ping result yet, assume it is slow.
	}
}

// NewRelayRouter returns a life cycle hook that routes peers via relays in libp2p by
// continuously adding peer relay addresses to libp2p peer store.
func NewRelayRouter(tcpNode host.Host, peers []peer.ID, relays []*MutablePeer) lifecycle.HookFuncCtx {
	return func(ctx context.Context) {
		if len(relays) == 0 {
			return
		}

		ctx = log.WithTopic(ctx, "p2p")

		for ctx.Err() == nil {
			for _, pID := range peers {
				if pID == tcpNode.ID() {
					// Skip self
					continue
				}

				for _, mutable := range relays {
					relay, ok := mutable.Peer()
					if !ok {
						continue
					}

					relayAddrs, err := multiAddrsViaRelay(relay, pID)
					if err != nil {
						log.Error(ctx, "Failed discovering peer address", err)
						continue
					}

					tcpNode.Peerstore().AddAddrs(pID, relayAddrs, routedAddrTTL)
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

func isErrProtocolNotSupported(err error) bool {
	return errors.Is(err, multistream.ErrNotSupported[protocol.ID]{}) ||
		errors.Is(err, multistream.ErrNotSupported[string]{})
}
