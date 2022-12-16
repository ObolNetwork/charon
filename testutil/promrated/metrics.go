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
	uptime = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "rated",
		Subsystem: "sentinel",
		Name:      "validation_key_uptime",
		Help:      "Uptime of a validation key.",
	}, []string{"pubkey_full", "cluster_name", "cluster_hash", "cluster_network"})

	correctness = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "rated",
		Subsystem: "sentinel",
		Name:      "validation_key_correctness",
		Help:      "Average correctness of a validation key.",
	}, []string{"pubkey_full", "cluster_name", "cluster_hash", "cluster_network"})

	inclusionDelay = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "rated",
		Subsystem: "sentinel",
		Name:      "validation_key_inclusion_delay",
		Help:      "Average inclusion delay of a validation key.",
	}, []string{"pubkey_full", "cluster_name", "cluster_hash", "cluster_network"})

	attester = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "rated",
		Subsystem: "sentinel",
		Name:      "validation_key_attester_effectiveness",
		Help:      "Attester effectiveness of a validation key.",
	}, []string{"pubkey_full", "cluster_name", "cluster_hash", "cluster_network"})

	proposer = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "rated",
		Subsystem: "sentinel",
		Name:      "validation_key_proposer_effectiveness",
		Help:      "Proposer effectiveness of a validation key.",
	}, []string{"pubkey_full", "cluster_name", "cluster_hash", "cluster_network"})

	effectiveness = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "rated",
		Subsystem: "sentinel",
		Name:      "validation_key_effectiveness",
		Help:      "Effectiveness of a validation key.",
	}, []string{"pubkey_full", "cluster_name", "cluster_hash", "cluster_network"})
)
