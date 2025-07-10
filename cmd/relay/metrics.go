// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
