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

package promrated

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

var (
	labels = []string{"pubkey_full", "cluster_name", "cluster_hash", "cluster_network"}

	uptime = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "promrated",
		Name:      "validator_uptime",
		Help:      "Uptime of a validation key.",
	}, labels)

	correctness = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "promrated",
		Name:      "validator_correctness",
		Help:      "Average correctness of a validation key.",
	}, labels)

	inclusionDelay = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "promrated",
		Name:      "validator_inclusion_delay",
		Help:      "Average inclusion delay of a validation key.",
	}, labels)

	attester = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "promrated",
		Name:      "validator_attester_effectiveness",
		Help:      "Attester effectiveness of a validation key.",
	}, labels)

	proposer = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "promrated",
		Name:      "validator_proposer_effectiveness",
		Help:      "Proposer effectiveness of a validation key.",
	}, labels)

	effectiveness = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "promrated",
		Name:      "validator_effectiveness",
		Help:      "Effectiveness of a validation key.",
	}, labels)

	ratedErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "promrated",
		Name:      "api_error_total",
		Help:      "Total number of rated api errors",
	}, []string{"peer"})
)
