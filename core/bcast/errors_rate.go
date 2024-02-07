// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package bcast

import "github.com/obolnetwork/charon/core"

const (
	// RegistrationErrorsRateThreshold defines the threshold for registration errors rate.
	RegistrationErrorsRateThreshold = 70.0
)

// errorsRate object tracks registration errors rate within the last two epochs and updates metrics.
type errorsRate struct {
	pregenState     rateState
	downstreamState rateState
}

// rateState represents single rate evaluation state.
type rateState struct {
	total    int
	errors   int
	prevRate float64
}

// incrementTotal() increments the total counters.
func (r *errorsRate) incrementTotal(duty core.Duty) {
	if duty.Type != core.DutyBuilderRegistration {
		return
	}

	if duty.Slot == 0 {
		r.pregenState.total++
	} else {
		r.downstreamState.total++
	}
}

// incrementErrors() increments the error counters.
func (r *errorsRate) incrementErrors(duty core.Duty) {
	if duty.Type != core.DutyBuilderRegistration {
		return
	}

	if duty.Slot == 0 {
		r.pregenState.errors++
	} else {
		r.downstreamState.errors++
	}
}

// updateMetrics() updates metrics if a rate reached the threshold.
func (r *errorsRate) updateMetrics() {
	currentPregenRate := calculateRate(r.pregenState)
	currentDownstreamRate := calculateRate(r.downstreamState)

	// We want to be tolerant of the request failing in a single epoch, and warn when it happens for two consecutive epochs.
	if r.pregenState.prevRate >= RegistrationErrorsRateThreshold && currentPregenRate >= RegistrationErrorsRateThreshold {
		recastErrorsRate.WithLabelValues(regSourcePregen).Set(currentPregenRate)
	} else {
		recastErrorsRate.WithLabelValues(regSourcePregen).Set(0)
	}

	if r.downstreamState.prevRate >= RegistrationErrorsRateThreshold && currentDownstreamRate >= RegistrationErrorsRateThreshold {
		recastErrorsRate.WithLabelValues(regSourceDownstream).Set(currentDownstreamRate)
	} else {
		recastErrorsRate.WithLabelValues(regSourceDownstream).Set(0)
	}

	r.pregenState.prevRate = currentPregenRate
	r.downstreamState.prevRate = currentDownstreamRate
}

// calculateRate() returns the calculated rate in percent for given values.
func calculateRate(state rateState) float64 {
	if state.total == 0 {
		return 0
	}

	return float64(state.errors) * 100.0 / float64(state.total)
}
