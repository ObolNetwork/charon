// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p

import (
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

const (
	addrTypeRelay  = "relay"
	addrTypeDirect = "direct"
)

var (
	pingLatencies = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "p2p",
		Name:      "ping_latency_secs",
		Help:      "Ping latencies in seconds per peer",
	}, []string{"peer"})

	pingErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "p2p",
		Name:      "ping_error_total",
		Help:      "Total number of ping errors per peer",
	}, []string{"peer"})

	pingSuccess = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "p2p",
		Name:      "ping_success",
		Help:      "Whether the last ping was successful (1) or not (0). Can be used as proxy for connected peers",
	}, []string{"peer"})

	reachableGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "p2p",
		Name:      "reachability_status",
		Help:      "Current libp2p reachability status of this node as detected by autonat: unknown(0), public(1) or private(2).",
	})

	relayConnGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "p2p",
		Name:      "relay_connections",
		Help:      "Connected relays by name",
	}, []string{"peer"})

	peerConnGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "p2p",
		Name:      "peer_connection_types",
		Help:      "Current number of libp2p connections by peer and type ('direct' or 'relay'). Note that peers may have multiple connections.",
	}, []string{"peer", "type"})

	peerConnCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "p2p",
		Name:      "peer_connection_total",
		Help:      "Total number of libp2p connections per peer.",
	}, []string{"peer"})

	networkRXCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "p2p",
		Name:      "peer_network_receive_bytes_total",
		Help:      "Total number of network bytes received from the peer by protocol.",
	}, []string{"peer", "protocol"})

	networkTXCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "p2p",
		Name:      "peer_network_sent_bytes_total",
		Help:      "Total number of network bytes sent to the peer by protocol.",
	}, []string{"peer", "protocol"})
)

func observePing(p peer.ID, d time.Duration) {
	pingLatencies.WithLabelValues(PeerName(p)).Observe(d.Seconds())
	pingSuccess.WithLabelValues(PeerName(p)).Set(1)
}

func incPingError(p peer.ID) {
	pingErrors.WithLabelValues(PeerName(p)).Inc()
	pingSuccess.WithLabelValues(PeerName(p)).Set(0)
}
