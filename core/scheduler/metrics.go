// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package scheduler

import (
	"sync"

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

	statusGauge = promauto.NewResetGaugeVec(prometheus.GaugeOpts{
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

	submitRegistrationCounter = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "scheduler",
		Name:      "submit_registration_total",
		Help:      "The total number of submit registration requests",
	})

	submitRegistrationErrors = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "scheduler",
		Name:      "submit_registration_errors_total",
		Help:      "The total count of failed submit registration requests",
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

// newMetricSubmitter returns a function that sets validator balance and status metrics
// and a sweep function that deletes the metrics of validators not submitted since the
// previous sweep, preventing stale series accumulating when validators are removed.
func newMetricSubmitter() (metricSubmitter, func()) {
	var (
		mu      sync.Mutex
		active  = make(map[core.PubKey]bool)
		current = make(map[core.PubKey]bool)
	)

	submit := func(pubkey core.PubKey, totalBal eth2p0.Gwei, status string) {
		balanceGauge.WithLabelValues(string(pubkey), pubkey.String()).Set(float64(totalBal))

		statusGauge.Reset(string(pubkey), pubkey.String())
		statusGauge.WithLabelValues(string(pubkey), pubkey.String(), status).Set(1)

		mu.Lock()
		current[pubkey] = true
		mu.Unlock()
	}

	sweep := func() {
		mu.Lock()
		defer mu.Unlock()

		for pubkey := range active {
			if current[pubkey] {
				continue
			}

			balanceGauge.DeleteLabelValues(string(pubkey), pubkey.String())
			statusGauge.Reset(string(pubkey), pubkey.String())
		}

		active = current
		current = make(map[core.PubKey]bool)
	}

	return submit, sweep
}
