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

package bootnode

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"time"

	relaylog "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/metrics"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/peerinfo"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/p2p"
)

// startP2P returns a started libp2p host or an error.
func startP2P(ctx context.Context, config Config, key *ecdsa.PrivateKey, reporter metrics.Reporter) (host.Host, error) {
	if config.RelayLogLevel != "" {
		if err := relaylog.SetLogLevel("relay", config.RelayLogLevel); err != nil {
			return nil, errors.Wrap(err, "set relay log level")
		}
	}

	// Increase resource limits
	limiter := rcmgr.DefaultLimits
	limiter.SystemBaseLimit.ConnsInbound = config.MaxConns
	limiter.SystemBaseLimit.FD = config.MaxConns
	limiter.TransientBaseLimit = limiter.SystemBaseLimit

	mgr, err := rcmgr.NewResourceManager(rcmgr.NewFixedLimiter(limiter.Scale(1<<30, config.MaxConns))) // 1GB Memory
	if err != nil {
		return nil, errors.Wrap(err, "new resource manager")
	}

	tcpNode, err := p2p.NewTCPNode(ctx, config.P2PConfig, key, p2p.NewOpenGater(),
		libp2p.ResourceManager(mgr), libp2p.BandwidthReporter(reporter))
	if err != nil {
		return nil, errors.Wrap(err, "new tcp node")
	}

	p2p.RegisterConnectionLogger(tcpNode, nil)

	// Reservations are valid for 30min (github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay/constraints.go:14)
	relayResources := relay.DefaultResources()
	relayResources.Limit.Data = 32 * (1 << 20) // 32MB
	relayResources.MaxReservationsPerPeer = config.MaxResPerPeer
	relayResources.MaxReservationsPerIP = config.MaxResPerPeer
	relayResources.MaxReservations = config.MaxConns
	relayResources.MaxCircuits = config.MaxResPerPeer

	relayService, err := relay.New(tcpNode, relay.WithResources(relayResources))
	if err != nil {
		return nil, errors.Wrap(err, "new relay service")
	}

	go func() {
		<-ctx.Done()
		_ = tcpNode.Close()
		_ = relayService.Close()
	}()

	return tcpNode, nil
}

const unknownCluster = "unknown"

// monitorConnections blocks instrumenting peer connection metrics until the context is closed.
func monitorConnections(ctx context.Context, tcpNode host.Host, reporter metrics.Reporter) {
	// peerConns tracks connection data per peer.
	type peerConns struct {
		Active int
		New    int
	}
	// peerInfo combines peer ID with cluster hash.
	type peerInfo struct {
		ID          peer.ID
		ClusterHash string
	}

	// State
	var (
		infos  = make(chan peerInfo)
		peers  = make(map[peer.ID]peerConns)
		events = make(chan connEvent)
	)

	// Listen for connection events.
	tcpNode.Network().Notify(&connLogger{events: events})

	// Schedule regular peerinfo requests to all peers.
	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case info := <-infos:
			// Instrument peer every time we get peerinfo respsonse
			conns, ok := peers[info.ID]
			if !ok {
				continue // Peer not connected anymore
			}
			name := p2p.PeerName(info.ID)
			stats := reporter.GetBandwidthForPeer(info.ID)

			bandwidthInGauge.WithLabelValues(info.ClusterHash, name).Set(stats.RateIn)
			bandwidthOutGauge.WithLabelValues(info.ClusterHash, name).Set(stats.RateOut)
			newConnsCounter.WithLabelValues(info.ClusterHash, name).Add(float64(conns.New))

			// Reset new connection state
			conns.New = 0
			peers[info.ID] = conns

		case e := <-events:
			// Update peer connection data on libp2p events.
			conns := peers[e.Peer]
			if e.Connected {
				conns.Active++
				conns.New++
			} else {
				conns.Active--
			}
			if conns.Active == 0 {
				delete(peers, e.Peer)
			} else {
				peers[e.Peer] = conns
			}
		case <-ticker.C:
			// Periodically request peerinfo for all peers we have connection data for.
			for p := range peers {
				go func(p peer.ID) {
					name := p2p.PeerName(p)
					var hash string
					info, rtt, ok, err := peerinfo.DoOnce(ctx, tcpNode, p)
					if p2p.IsRelayError(err) {
						// Ignore relay errors, since peer probably not connected anymore.
						return
					} else if err != nil {
						// Log other errors, but peer probably not connected anymore.
						log.Warn(ctx, "Protocol peerinfo failed", err, z.Str("peer", name))
						return
					} else if !ok {
						// Group peers that don't support the protocol with unknown cluster hash.
						hash = unknownCluster
					} else {
						hash = clusterHash(info.LockHash)
						peerPingLatency.WithLabelValues(hash, name).Observe(rtt.Seconds() / 2)
					}

					//  Enqueue peer for instrumentation (async since blocking)
					go func() {
						infos <- peerInfo{ClusterHash: hash, ID: p}
					}()
				}(p)
			}
		}
	}
}

// clusterHash returns the cluster hash hex from the lock hash.
func clusterHash(lockHash []byte) string {
	return hex.EncodeToString(lockHash)[:7]
}

// connEvent is a connection event.
type connEvent struct {
	Connected bool
	Peer      peer.ID
}

// connLogger implements network.Notifee and only sends logEvents on a channel since
// it is used as a map key internally in libp2p, it cannot contain complex types.
type connLogger struct {
	events chan connEvent
}

func (l connLogger) Connected(_ network.Network, conn network.Conn) {
	l.events <- connEvent{
		Connected: true,
		Peer:      conn.RemotePeer(),
	}
}

func (l connLogger) Disconnected(_ network.Network, conn network.Conn) {
	l.events <- connEvent{
		Connected: false,
		Peer:      conn.RemotePeer(),
	}
}

func (connLogger) Listen(network.Network, ma.Multiaddr) {}

func (connLogger) ListenClose(network.Network, ma.Multiaddr) {}
