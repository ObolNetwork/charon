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

package consensus

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

var decidedRoundsGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: "core",
	Subsystem: "consensus",
	Name:      "decided_rounds",
	Help:      "Number of rounds it took to decide consensus instances by duty type.",
}, []string{"duty"}) // Using gauge since the value changes slowly, once per slot.
