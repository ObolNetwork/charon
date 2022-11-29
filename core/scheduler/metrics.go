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

package scheduler

import (
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
	"github.com/obolnetwork/charon/core"
)

// metricSubmitter submits validator balance and status metrics.
type metricSubmitter func(pubkey core.PubKey, totalBal eth2p0.Gwei, status string)

var (
	slotGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "core",
		Subsystem: "scheduler",
		Name:      "current_slot",
		Help:      "The current slot",
	})

	epochGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "core",
		Subsystem: "scheduler",
		Name:      "current_epoch",
		Help:      "The current epoch",
	})

	dutyCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "scheduler",
		Name:      "duty_total",
		Help:      "The total count of duties scheduled by type",
	}, []string{"duty"})

	activeValsGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "core",
		Subsystem: "scheduler",
		Name:      "validators_active",
		Help:      "Number of active validators",
	})

	balanceGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "core",
		Subsystem: "scheduler",
		Name:      "validator_balance_gwei",
		Help:      "Total balance of a validator by public key",
	}, []string{"pubkey_full", "pubkey"})

	statusGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "core",
		Subsystem: "scheduler",
		Name:      "validator_status",
		Help:      "Constant gauge with label set to current status of the validator by pubkey",
	}, []string{"pubkey_full", "pubkey", "status"})

	skipCounter = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "scheduler",
		Name:      "skipped_slots_total",
		Help:      "Total number times slots were skipped",
	})
)

// instrumentSlot sets the current slot and epoch metrics.
func instrumentSlot(slot core.Slot) {
	slotGauge.Set(float64(slot.Slot))
	epochGauge.Set(float64(slot.Epoch()))
}

// instrumentDuty increments the duty counter.
func instrumentDuty(duty core.Duty, defSet core.DutyDefinitionSet) {
	dutyCounter.WithLabelValues(duty.Type.String()).Add(float64(len(defSet)))
}

// newMetricSubmitter returns a function that sets validator balance and status metric.
func newMetricSubmitter() func(pubkey core.PubKey, totalBal eth2p0.Gwei, status string) {
	var (
		prevBal    = make(map[core.PubKey]eth2p0.Gwei)
		prevStatus = make(map[core.PubKey]string)
	)

	return func(pubkey core.PubKey, totalBal eth2p0.Gwei, status string) {
		balanceGauge.WithLabelValues(string(pubkey), pubkey.String()).Set(float64(totalBal))
		statusGauge.WithLabelValues(string(pubkey), pubkey.String(), status).Set(1)

		if prev, ok := prevStatus[pubkey]; ok && prev != status { // Validator status changed
			statusGauge.WithLabelValues(string(pubkey), pubkey.String(), prev).Set(0)
		}
		if prev, ok := prevBal[pubkey]; ok && prev != totalBal { // Validator balance changed
			balanceGauge.WithLabelValues(string(pubkey), pubkey.String()).Set(0)
		}

		prevBal[pubkey] = totalBal
		prevStatus[pubkey] = status
	}
}
