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

package tracker2

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

var (
	participationGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "core",
		Subsystem: "tracker2",
		Name:      "participation",
		Help:      "Set to 1 if peer participated successfully for the given duty or else 0",
	}, []string{"duty", "peer"})

	participationCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "tracker2",
		Name:      "participation_total",
		Help:      "Total number of successful participations by peer and duty type",
	}, []string{"duty", "peer"})

	failedCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "tracker2",
		Name:      "failed_duties_total",
		Help:      "Total number of failed duties by type",
	}, []string{"duty"})

	unexpectedEventsCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "tracker2",
		Name:      "unexpected_events_total",
		Help:      "Total number of unexpected events by peer",
	}, []string{"peer"})

	inconsistentCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "tracker2",
		Name:      "inconsistent_parsigs_total",
		Help:      "Total number of duties that contained inconsistent partial signed data by duty type",
	}, []string{"duty"})
)
