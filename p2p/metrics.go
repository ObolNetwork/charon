// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p

import (
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/metrics"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

const (
	addrTypeRelay  = "relay"
	addrTypeDirect = "direct"

	protocolTCP     = "tcp"
	protocolQUIC    = "quic"
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

	peerConnTypeGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "p2p",
		Name:      "peer_connection_types",
		Help:      "Current number of libp2p connections by peer, type (`direct` or `relay`), and protocol (`tcp`, `quic`). Note that peers may have multiple connections.",
	}, []string{"peer", "type", "protocol"})

	relayConnTypeGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "p2p",
		Name:      "relay_connection_types",
		Help:      "Current number of libp2p connections by relay, type (`direct` or `relay`), and protocol (`tcp`, `quic`). Note that peers may have multiple connections.",
	}, []string{"peer", "type", "protocol"})

	peerStreamGauge = promauto.NewResetGaugeVec(prometheus.GaugeOpts{
		Namespace: "p2p",
		Name:      "peer_streams",
		Help:      "Current number of libp2p streams by peer, direction ('inbound' or 'outbound' or 'unknown'), protocol and transport.",
	}, []string{"peer", "direction", "protocol", "transport"})

	peerConnCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "p2p",
		Name:      "peer_connection_total",
		Help:      "Total number of libp2p connections per peer.",
	}, []string{"peer"})

	networkRXCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "p2p",
		Name:      "peer_network_receive_bytes_total",
		Help:      "Total number of network bytes received from the peer by protocol and transport. Transport is based on first active connection (accurate in steady state).",
	}, []string{"peer", "protocol", "transport"})

	networkTXCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "p2p",
		Name:      "peer_network_sent_bytes_total",
		Help:      "Total number of network bytes sent to the peer by protocol and transport. Transport is based on first active connection (accurate in steady state).",
	}, []string{"peer", "protocol", "transport"})
)

func observePing(p peer.ID, d time.Duration) {
	pingLatencies.WithLabelValues(PeerName(p)).Observe(d.Seconds())
	pingSuccess.WithLabelValues(PeerName(p)).Set(1)
}

func incPingError(p peer.ID) {
	pingErrors.WithLabelValues(PeerName(p)).Inc()
	pingSuccess.WithLabelValues(PeerName(p)).Set(0)
}

// WithSwarmMetrics returns a libp2p swarm option that enables the built-in swarm metrics.
// The registerer parameter should be the same prometheus registry used by the application
// to ensure libp2p metrics are exposed alongside application metrics.
func WithSwarmMetrics(registerer prometheus.Registerer) swarm.Option {
	// Use libp2p's built-in metrics tracer with the provided registerer
	return swarm.WithMetricsTracer(swarm.NewMetricsTracer(swarm.WithRegisterer(registerer)))
}

// BandwidthReporter is an interface for the bandwidth reporter that can be registered with a host.
type BandwidthReporter interface {
	registerHost(host.Host)
}

var _ metrics.Reporter = (*bandwithReporter)(nil)

// WithBandwidthReporter returns a libp2p option that enables bandwidth reporting via prometheus.
// Returns both the option and the reporter instance so the host can be registered later.
func WithBandwidthReporter(peers []peer.ID) (libp2p.Option, BandwidthReporter) {
	peerNames := make(map[peer.ID]string)
	for _, p := range peers {
		peerNames[p] = PeerName(p)
	}

	reporter := &bandwithReporter{
		peerNames: peerNames,
	}

	return libp2p.BandwidthReporter(reporter), reporter
}

// RegisterBandwidthReporter sets the host reference on the bandwidth reporter for transport detection.
func RegisterBandwidthReporter(reporter BandwidthReporter, h host.Host) {
	if reporter != nil {
		reporter.registerHost(h)
	}
}

type bandwithReporter struct {
	metrics.Reporter

	host      host.Host
	peerNames map[peer.ID]string
}

func (r *bandwithReporter) registerHost(h host.Host) {
	r.host = h
}

func (bandwithReporter) LogSentMessage(int64) {}

func (bandwithReporter) LogRecvMessage(int64) {}

func (r *bandwithReporter) LogSentMessageStream(bytes int64, protoID protocol.ID, peerID peer.ID) {
	name, ok := r.peerNames[peerID]
	if !ok {
		return // Do not instrument relays
	}

	transport := r.getTransportProtocol(peerID)
	networkTXCounter.WithLabelValues(name, string(protoID), transport).Add(float64(bytes))
}

func (r *bandwithReporter) LogRecvMessageStream(bytes int64, protoID protocol.ID, peerID peer.ID) {
	name, ok := r.peerNames[peerID]
	if !ok {
		return // Do not instrument relays
	}

	transport := r.getTransportProtocol(peerID)
	networkRXCounter.WithLabelValues(name, string(protoID), transport).Add(float64(bytes))
}

// getTransportProtocol determines the transport protocol (tcp/quic/unknown) for a peer.
// Uses first connection which is accurate in steady state (single connection per peer).
func (r *bandwithReporter) getTransportProtocol(peerID peer.ID) string {
	if r.host == nil {
		return protocolUnknown
	}

	conns := r.host.Network().ConnsToPeer(peerID)
	if len(conns) == 0 {
		return protocolUnknown
	}

	// In steady state, there's typically only one connection per peer.
	// Use first connection's protocol.
	return addrProtocol(conns[0].RemoteMultiaddr())
}
