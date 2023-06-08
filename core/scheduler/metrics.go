// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
		Help:      "Gauge with validator pubkey and status as labels, value=1 is current status, value=0 is previous.",
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
	// TODO(corver): Refactor to use ResetGauge.
	prevStatus := make(map[core.PubKey]string)

	return func(pubkey core.PubKey, totalBal eth2p0.Gwei, status string) {
		balanceGauge.WithLabelValues(string(pubkey), pubkey.String()).Set(float64(totalBal))
		statusGauge.WithLabelValues(string(pubkey), pubkey.String(), status).Set(1)

		if prev, ok := prevStatus[pubkey]; ok && prev != status { // Validator status changed
			statusGauge.WithLabelValues(string(pubkey), pubkey.String(), prev).Set(0)
		}
		prevStatus[pubkey] = status
	}
}
