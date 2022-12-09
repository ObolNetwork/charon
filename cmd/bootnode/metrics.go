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
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

var (
	newConnsCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "bootnode",
		Subsystem: "p2p",
		Name:      "connection_total",
		Help:      "Total number of connections by peer and cluster",
	}, []string{"peer", "peer_cluster"})

	bandwidthInGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "bootnode",
		Subsystem: "p2p",
		Name:      "bandwidth_in",
		Help:      "Bandwidth rate in by peer and cluster",
	}, []string{"peer", "peer_cluster"})

	bandwidthOutGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "bootnode",
		Subsystem: "p2p",
		Name:      "bandwidth_out",
		Help:      "Bandwidth rate out by peer and cluster",
	}, []string{"peer", "peer_cluster"})

	peerPingLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "bootnode",
		Subsystem: "p2p",
		Name:      "ping_latency",
		Help:      "Ping latency by peer and cluster",
	}, []string{"peer", "peer_cluster"})
)
