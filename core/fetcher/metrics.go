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

package fetcher

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

// TODO(dhruv): Remove the inconsistent counter code after the data has been collected.
var inconsistentAttDataCounter = promauto.NewCounter(prometheus.CounterOpts{
	Namespace: "core",
	Subsystem: "fetcher",
	Name:      "inconsistent_att_data_total",
	Help:      "Total number of inconsistent attestation data detected. Note this is expected.",
})
