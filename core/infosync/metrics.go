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

package infosync

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

const (
	// resultEmpty indicates that insufficient peers exchanged the same priorities so cluster-wide priorities
	// could not be calculated.
	resultEmpty = "empty"
	// resultOwn indicates that resulting cluster-wide priorities match this node's own priorities.
	resultOwn = "own"
	// resultOther indicates that resulting cluster-wide priorities are different from this node's own priorities.
	resultOther = "other"
)

var completeCounter = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "core",
	Subsystem: "infosync",
	Name:      "complete_total",
	Help:      "Total number of infosync instances completed by result: empty, own or other",
}, []string{"result"})
