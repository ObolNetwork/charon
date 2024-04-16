// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package relay

import (
	"context"

	"github.com/libp2p/go-libp2p/core/metrics"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

var (
	newConnsCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "relay",
		Subsystem: "p2p",
		Name:      "connection_total",
		Help:      "Total number of new connections by peer and cluster",
	}, []string{"peer", "peer_cluster"})

	activeConnsCounter = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "relay",
		Subsystem: "p2p",
		Name:      "active_connections",
		Help:      "Current number of active connections by peer and cluster",
	}, []string{"peer", "peer_cluster"})

	networkTXCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "relay",
		Subsystem: "p2p",
		Name:      "network_sent_bytes_total",
		Help:      "Total number of network bytes sent to the peer and cluster",
	}, []string{"peer", "peer_cluster"})

	networkRXCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "relay",
		Subsystem: "p2p",
		Name:      "network_receive_bytes_total",
		Help:      "Total number of network bytes received from the peer and cluster",
	}, []string{"peer", "peer_cluster"})

	peerPingLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "relay",
		Subsystem: "p2p",
		Name:      "ping_latency",
		Help:      "Ping latency by peer and cluster",
	}, []string{"peer", "peer_cluster"})

	// Relay metrics produced by libp2p.
	// These are prefixed with "int_" to avoid conflicts with other metrics.

	intStatus = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "relay",
			Subsystem: "p2p",
			Name:      "int_status",
			Help:      "Relay Status",
		},
	)

	intReservationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "relay",
			Subsystem: "p2p",
			Name:      "int_reservations_total",
			Help:      "Relay Reservation Request",
		},
		[]string{"type"},
	)

	intReservationRequestResponseStatusTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "relay",
			Subsystem: "p2p",
			Name:      "int_reservation_request_response_status_total",
			Help:      "Relay Reservation Request Response Status",
		},
		[]string{"status"},
	)

	intReservationRejectionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "relay",
			Subsystem: "p2p",
			Name:      "int_reservation_rejections_total",
			Help:      "Relay Reservation Rejected Reason",
		},
		[]string{"reason"},
	)

	intConnectionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "relay",
			Subsystem: "p2p",
			Name:      "int_connections_total",
			Help:      "Relay Connection Total",
		},
		[]string{"type"},
	)

	intConnectionRequestResponseStatusTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "relay",
			Subsystem: "p2p",
			Name:      "int_connection_request_response_status_total",
			Help:      "Relay Connection Request Status",
		},
		[]string{"status"},
	)

	intConnectionRejectionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "relay",
			Subsystem: "p2p",
			Name:      "int_connection_rejections_total",
			Help:      "Relay Connection Rejected Reason",
		},
		[]string{"reason"},
	)

	intConnectionDurationSeconds = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "relay",
			Subsystem: "p2p",
			Name:      "int_connection_duration_seconds",
			Help:      "Relay Connection Duration",
		},
	)

	intDataTransferredBytesTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "relay",
			Subsystem: "p2p",
			Name:      "int_data_transferred_bytes_total",
			Help:      "Bytes Transferred Total",
		},
	)
)

// newBandwidthCounter returns a new bandwidth counter that stops counting when the context is cancelled.
func newBandwidthCounter(ctx context.Context, ch chan<- bwTuple) metrics.Reporter {
	return bwCounter{
		ch:   ch,
		done: ctx.Done(),
	}
}

// bwTuple is a bandwidth counter tuple.
type bwTuple struct {
	ID   peer.ID
	Size int64
	Sent bool
}

// bwCounter is a bandwidth counter implementing libp2p metrics.Reporter.
type bwCounter struct {
	metrics.Reporter
	done <-chan struct{}
	ch   chan<- bwTuple
}

func (bwCounter) LogSentMessage(int64) {}

func (bwCounter) LogRecvMessage(int64) {}

func (b bwCounter) LogSentMessageStream(size int64, _ protocol.ID, pID peer.ID) {
	select {
	case b.ch <- bwTuple{ID: pID, Size: size, Sent: true}:
	case <-b.done:
	}
}

func (b bwCounter) LogRecvMessageStream(size int64, _ protocol.ID, pID peer.ID) {
	select {
	case b.ch <- bwTuple{ID: pID, Size: size, Sent: false}:
	case <-b.done:
	}
}
