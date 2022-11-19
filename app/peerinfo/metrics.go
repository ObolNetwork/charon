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

package peerinfo

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

var (
	peerClockOffset = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace:   "app",
		Subsystem:   "peerinfo",
		Name:        "clock_offset_seconds",
		Help:        "Peer clock offset in seconds",
		ConstLabels: nil,
	}, []string{"peer"})

	peerVersion = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace:   "app",
		Subsystem:   "peerinfo",
		Name:        "version",
		Help:        "Constant gauge with version label set to peer's charon version.",
		ConstLabels: nil,
	}, []string{"peer", "version"})

	peerGitHash = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace:   "app",
		Subsystem:   "peerinfo",
		Name:        "git_commit",
		Help:        "Constant gauge with git_hash label set to peer's git commit hash.",
		ConstLabels: nil,
	}, []string{"peer", "git_hash"})

	peerStartGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "app",
		Subsystem: "peerinfo",
		Name:      "start_time_secs",
		Help:      "Constant gauge set to the peer start time of the binary in unix seconds",
	}, []string{"peer"})

	peerIndexGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "app",
		Subsystem: "peerinfo",
		Name:      "index",
		Help:      "Constant gauge set to the peer index in the cluster definition",
	}, []string{"peer"})
)
