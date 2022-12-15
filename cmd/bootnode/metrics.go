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

	"github.com/libp2p/go-libp2p/core/metrics"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

var (
	newConnsCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "bootnode",
		Subsystem: "p2p",
		Name:      "connection_total",
		Help:      "Total number of new connections by peer and cluster",
	}, []string{"peer", "peer_cluster"})

	activeConnsCounter = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "bootnode",
		Subsystem: "p2p",
		Name:      "active_connections",
		Help:      "Current number of active connections by peer and cluster",
	}, []string{"peer", "peer_cluster"})

	networkTXCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "bootnode",
		Subsystem: "p2p",
		Name:      "network_sent_bytes_total",
		Help:      "Total number of network bytes sent to the peer and cluster",
	}, []string{"peer", "peer_cluster"})

	networkRXCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "bootnode",
		Subsystem: "p2p",
		Name:      "network_receive_bytes_total",
		Help:      "Total number of network bytes received from the peer and cluster",
	}, []string{"peer", "peer_cluster"})

	peerPingLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "bootnode",
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
