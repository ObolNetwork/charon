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

package bcast

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/obolnetwork/charon/core"
)

var broadcastCounter = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "core",
	Subsystem: "bcast",
	Name:      "broadcast_total",
	Help:      "The total count of successfully broadcast duties by pubkey and type",
}, []string{"type", "pubkey"})

// instrumentDuty increments the duty counter.
func instrumentDuty(duty core.Duty, pubkey core.PubKey) {
	broadcastCounter.WithLabelValues(duty.Type.String(), pubkey.String()).Inc()
}
