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

package p2p

import (
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
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
)

func observePing(p peer.ID, d time.Duration) {
	pingLatencies.WithLabelValues(PeerName(p)).Observe(d.Seconds())
	pingSuccess.WithLabelValues(PeerName(p)).Set(1)
}

func incPingError(p peer.ID) {
	pingErrors.WithLabelValues(PeerName(p)).Inc()
	pingSuccess.WithLabelValues(PeerName(p)).Set(0)
}
