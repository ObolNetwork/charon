// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p

import (
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/metrics"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

const (
	addrTypeRelay  = "relay"
	addrTypeDirect = "direct"

	protocolTCP     = "tcp"
	protocolQUIC    = "quic"
	protocolUDP     = "udp"
	protocolUnknown = "unknown"
	protocolNone    = "none"
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
		Help:      "Current number of libp2p connections by peer, type ('direct' or 'relay'), and protocol ('tcp', 'quic', etc.). Note that peers may have multiple connections.",
	}, []string{"peer", "type", "protocol"})

	peerStreamGauge = promauto.NewResetGaugeVec(prometheus.GaugeOpts{
		Namespace: "p2p",
		Name:      "peer_streams",
		Help:      "Current number of libp2p streams by peer, direction ('inbound' or 'outbound' or 'unknown') and protocol.",
	}, []string{"peer", "direction", "protocol"})

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

var _ metrics.Reporter = bandwithReporter{}

// WithBandwidthReporter returns a libp2p option that enables bandwidth reporting via prometheus.
func WithBandwidthReporter(peers []peer.ID) libp2p.Option {
	peerNames := make(map[peer.ID]string)
	for _, p := range peers {
		peerNames[p] = PeerName(p)
	}

	return libp2p.BandwidthReporter(bandwithReporter{peerNames: peerNames})
}

type bandwithReporter struct {
	metrics.Reporter

	peerNames map[peer.ID]string
}

func (bandwithReporter) LogSentMessage(int64) {}

func (bandwithReporter) LogRecvMessage(int64) {}

func (r bandwithReporter) LogSentMessageStream(bytes int64, protoID protocol.ID, peerID peer.ID) {
	name, ok := r.peerNames[peerID]
	if !ok {
		return // Do not instrument relays
	}

	networkTXCounter.WithLabelValues(name, string(protoID)).Add(float64(bytes))
}

func (r bandwithReporter) LogRecvMessageStream(bytes int64, protoID protocol.ID, peerID peer.ID) {
	name, ok := r.peerNames[peerID]
	if !ok {
		return // Do not instrument relays
	}

	networkRXCounter.WithLabelValues(name, string(protoID)).Add(float64(bytes))
}
