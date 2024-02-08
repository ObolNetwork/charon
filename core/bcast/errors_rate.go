// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package bcast

import (
	"sync/atomic"

	"github.com/obolnetwork/charon/core"
)

const (
	// RegistrationErrorsRateThreshold defines the threshold for registration errors rate.
	RegistrationErrorsRateThreshold int32 = 70
)

// errorsRate object tracks registration errors rate within the last two epochs and updates metrics.
type errorsRate struct {
	pregenState     rateState
	downstreamState rateState
}

// rateState represents single rate evaluation state.
type rateState struct {
	total    atomic.Int32
	errors   atomic.Int32
	prevRate atomic.Int32
}

// incrementTotal() increments the total counters.
func (r *errorsRate) incrementTotal(duty core.Duty) {
	if duty.Type != core.DutyBuilderRegistration {
		return
	}

	if duty.Slot == 0 {
		r.pregenState.total.Add(1)
	} else {
		r.downstreamState.total.Add(1)
	}
}

// incrementErrors() increments the error counters.
func (r *errorsRate) incrementErrors(duty core.Duty) {
	if duty.Type != core.DutyBuilderRegistration {
		return
	}

	if duty.Slot == 0 {
		r.pregenState.errors.Add(1)
	} else {
		r.downstreamState.errors.Add(1)
	}
}

// updateMetrics() updates metrics if a rate reached the threshold.
func (r *errorsRate) updateMetrics() {
	recastTotal.WithLabelValues(regSourcePregen).Add(float64(r.pregenState.total.Load()))
	recastErrors.WithLabelValues(regSourcePregen).Add(float64(r.pregenState.errors.Load()))
	recastTotal.WithLabelValues(regSourceDownstream).Add(float64(r.downstreamState.total.Load()))
	recastErrors.WithLabelValues(regSourceDownstream).Add(float64(r.downstreamState.errors.Load()))

	currentPregenRate := calculateRate(&r.pregenState)
	currentDownstreamRate := calculateRate(&r.downstreamState)

	// We want to be tolerant of the request failing in a single epoch, and warn when it happens for two consecutive epochs.
	if r.pregenState.prevRate.Load() >= RegistrationErrorsRateThreshold && currentPregenRate >= RegistrationErrorsRateThreshold {
		recastErrorsRate.WithLabelValues(regSourcePregen).Set(float64(currentPregenRate))
	} else {
		recastErrorsRate.WithLabelValues(regSourcePregen).Set(0)
	}

	if r.downstreamState.prevRate.Load() >= RegistrationErrorsRateThreshold && currentDownstreamRate >= RegistrationErrorsRateThreshold {
		recastErrorsRate.WithLabelValues(regSourceDownstream).Set(float64(currentDownstreamRate))
	} else {
		recastErrorsRate.WithLabelValues(regSourceDownstream).Set(0)
	}

	r.pregenState.total.Store(0)
	r.pregenState.errors.Store(0)
	r.pregenState.prevRate.Store(currentPregenRate)

	r.downstreamState.total.Store(0)
	r.downstreamState.errors.Store(0)
	r.downstreamState.prevRate.Store(currentDownstreamRate)
}

// calculateRate() returns the calculated rate in percent for given values.
func calculateRate(state *rateState) int32 {
	if state.total.Load() == 0 {
		return 0
	}

	return state.errors.Load() * 100 / state.total.Load()
}
