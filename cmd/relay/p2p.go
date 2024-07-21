// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package relay

import (
	"context"
	"encoding/hex"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	libp2plog "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/metrics"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/peerinfo"
	"github.com/obolnetwork/charon/app/promauto"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/p2p"
)

// startP2P returns a started libp2p host or an error.
func startP2P(ctx context.Context, config Config, key *k1.PrivateKey, reporter metrics.Reporter) (host.Host, *prometheus.Registry, error) {
	if len(config.P2PConfig.TCPAddrs) == 0 {
		return nil, nil, errors.New("p2p TCP addresses required")
	}

	if config.LibP2PLogLevel != "" {
		if err := libp2plog.SetLogLevel("relay", config.LibP2PLogLevel); err != nil {
			return nil, nil, errors.Wrap(err, "set relay log level")
		}
		if err := libp2plog.SetLogLevel("rcmgr", config.LibP2PLogLevel); err != nil {
			return nil, nil, errors.Wrap(err, "set rcmgr log level")
		}
	}

	tcpNode, err := p2p.NewTCPNode(ctx, config.P2PConfig, key, p2p.NewOpenGater(), config.FilterPrivAddrs,
		libp2p.ResourceManager(new(network.NullResourceManager)), libp2p.BandwidthReporter(reporter))
	if err != nil {
		return nil, nil, errors.Wrap(err, "new tcp node")
	}

	p2p.RegisterConnectionLogger(ctx, tcpNode, nil)

	labels := map[string]string{"relay_peer": p2p.PeerName(tcpNode.ID())}
	log.SetLokiLabels(labels)
	promRegistry, err := promauto.NewRegistry(labels)
	if err != nil {
		return nil, nil, errors.Wrap(err, "create prometheus registry")
	}

	relayResources := relay.DefaultResources()
	relayResources.Limit.Data = 32 * (1 << 20) // 32MB
	relayResources.Limit.Duration = time.Hour
	relayResources.BufferSize = 64 * (1 << 10) // 64KB
	relayResources.MaxReservationsPerPeer = config.MaxResPerPeer
	relayResources.MaxReservationsPerIP = config.MaxResPerPeer
	relayResources.MaxReservations = config.MaxConns
	relayResources.MaxCircuits = config.MaxResPerPeer

	// This enables relay metrics: https://github.com/libp2p/go-libp2p/blob/master/p2p/protocol/circuitv2/relay/metrics.go
	mt := relay.NewMetricsTracer(relay.WithRegisterer(promRegistry))
	relayService, err := relay.New(tcpNode, relay.WithResources(relayResources), relay.WithMetricsTracer(mt))
	if err != nil {
		return nil, nil, errors.Wrap(err, "new relay service")
	}

	go func() {
		<-ctx.Done()
		_ = tcpNode.Close()
		_ = relayService.Close()
	}()

	return tcpNode, promRegistry, nil
}

const unknownCluster = "unknown"

// monitorConnections blocks instrumenting peer connection metrics until the context is closed.
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
			}
			state.ClusterHash = info.ClusterHash

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

	clusterHash := hex7(info.GetLockHash())
	peerPingLatency.WithLabelValues(name, clusterHash).Observe(rtt.Seconds() / 2)

	return clusterHash, true, nil
}

// hex7 returns the first 7 (or less) hex chars of the provided bytes.
func hex7(input []byte) string {
	resp := hex.EncodeToString(input)
	if len(resp) <= 7 {
		return resp
	}

	return resp[:7]
}

// connEvent is a connection event.
type connEvent struct {
	Connected bool
	Peer      peer.ID
}

// connLogger implements network.Notifiee and only sends logEvents on a channel since
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
