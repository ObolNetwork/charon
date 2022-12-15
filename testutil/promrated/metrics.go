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
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type watcherMetrics struct {
	RatedValidationUptime                 *prometheus.GaugeVec
	RatedValidationAvgCorrectness         *prometheus.GaugeVec
	RatedValidationAvgInclustionDelay     *prometheus.GaugeVec
	RatedValidationAttesterEffectiveness  *prometheus.GaugeVec
	RatedValidationProposerEffectiveness  *prometheus.GaugeVec
	RatedValidationValidatorEffectiveness *prometheus.GaugeVec
}

// newWatcherMetrics creates prometheus metrics for the watcher.
func newWatcherMetrics(reg prometheus.Registerer) *watcherMetrics {
	uptime := promauto.With(reg).NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "rated",
		Subsystem: "sentinel",
		Name:      "validation_key_uptime",
		Help:      "Uptime of a validation key.",
	}, []string{"pubkey_full", "cluster_name", "cluster_hash", "cluster_network"})

	correctness := promauto.With(reg).NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "rated",
		Subsystem: "sentinel",
		Name:      "validation_key_correctness",
		Help:      "Average correctness of a validation key.",
	}, []string{"pubkey_full", "cluster_name", "cluster_hash", "cluster_network"})

	inclusionDelay := promauto.With(reg).NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "rated",
		Subsystem: "sentinel",
		Name:      "validation_key_inclusion_delay",
		Help:      "Average inclusion delay of a validation key.",
	}, []string{"pubkey_full", "cluster_name", "cluster_hash", "cluster_network"})

	attester := promauto.With(reg).NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "rated",
		Subsystem: "sentinel",
		Name:      "validation_key_attester_effectiveness",
		Help:      "Attester effectiveness of a validation key.",
	}, []string{"pubkey_full", "cluster_name", "cluster_hash", "cluster_network"})

	proposer := promauto.With(reg).NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "rated",
		Subsystem: "sentinel",
		Name:      "validation_key_proposer_effectiveness",
		Help:      "Proposer effectiveness of a validation key.",
	}, []string{"pubkey_full", "cluster_name", "cluster_hash", "cluster_network"})

	effectiveness := promauto.With(reg).NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "rated",
		Subsystem: "sentinel",
		Name:      "validation_key_effectiveness",
		Help:      "Effectiveness of a validation key.",
	}, []string{"pubkey_full", "cluster_name", "cluster_hash", "cluster_network"})

	return &watcherMetrics{
		RatedValidationUptime:                 uptime,
		RatedValidationAvgCorrectness:         correctness,
		RatedValidationAvgInclustionDelay:     inclusionDelay,
		RatedValidationAttesterEffectiveness:  attester,
		RatedValidationProposerEffectiveness:  proposer,
		RatedValidationValidatorEffectiveness: effectiveness,
	}
}
