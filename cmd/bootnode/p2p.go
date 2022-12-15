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
//
//nolint:gocognit // Long but not complex.
func monitorConnections(ctx context.Context, tcpNode host.Host, bwTuples <-chan bwTuple) {
	// peerState tracks connection data per peer.
	type peerState struct {
		Active      int
		New         int
		Name        string
		ClusterHash string
	}
	// infoTuple combines peer ID with cluster hash.
	type infoTuple struct {
		ID          peer.ID
		ClusterHash string
	}

	// State
	var (
		infos  = make(chan infoTuple)
		peers  = make(map[peer.ID]peerState)
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
		case tuple := <-bwTuples:
			// Instrument bandwidth
			state, ok := peers[tuple.ID]
			if !ok {
				continue // Peer not connected anymore
			}
			if tuple.Sent {
				networkTXCounter.WithLabelValues(state.Name, state.ClusterHash).Add(float64(tuple.Size))
			} else {
				networkRXCounter.WithLabelValues(state.Name, state.ClusterHash).Add(float64(tuple.Size))
			}
		case info := <-infos:
			// Instrument peer every time we get peerinfo respsonse
			state, ok := peers[info.ID]
			if !ok {
				continue // Peer not connected anymore
			} else if state.ClusterHash != "" {
				state.ClusterHash = info.ClusterHash
			}

			newConnsCounter.WithLabelValues(state.Name, state.ClusterHash).Add(float64(state.New))
			activeConnsCounter.WithLabelValues(state.Name, state.ClusterHash).Set(float64(state.Active))

			// Reset new connection state
			state.New = 0
			peers[info.ID] = state
		case e := <-events:
			// Update peer connection data on libp2p events.
			state := peers[e.Peer]
			state.Name = p2p.PeerName(e.Peer)
			if e.Connected {
				state.Active++
				state.New++
			} else {
				state.Active--
			}
			peers[e.Peer] = state
		case <-ticker.C:
			// Periodically request peerinfo for all peers we have active connections to.
			for p, state := range peers {
				if state.Active == 0 {
					// No active connections, remove peer from state.
					delete(peers, p)

					if state.ClusterHash != "" {
						activeConnsCounter.WithLabelValues(state.Name, state.ClusterHash).Set(0)
					}

					continue
				}

				go func(p peer.ID, name string) {
					hash, ok, err := getPeerInfo(ctx, tcpNode, p, name)
					if err != nil {
						log.Warn(ctx, "Peerinfo failed", err, z.Str("peer", name))
						return
					} else if !ok {
						return
					}

					infos <- infoTuple{ClusterHash: hash, ID: p} //  Enqueue peer for instrumentation
				}(p, state.Name)
			}
		}
	}
}

// getPeerInfo returns the peer's cluster hash and true.
func getPeerInfo(ctx context.Context, tcpNode host.Host, pID peer.ID, name string) (string, bool, error) {
	info, rtt, ok, err := peerinfo.DoOnce(ctx, tcpNode, pID)
	if p2p.IsRelayError(err) {
		// Ignore relay errors, since peer probably not connected anymore.
		return "", false, nil
	} else if err != nil {
		return "", false, err
	} else if !ok {
		// Group peers that don't support the protocol with unknown cluster hash.
		return unknownCluster, true, nil
	}

	hash := clusterHash(info.LockHash)
	peerPingLatency.WithLabelValues(name, hash).Observe(rtt.Seconds() / 2)

	return hash, true, nil
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
