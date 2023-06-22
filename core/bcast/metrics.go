// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package bcast

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
	"github.com/obolnetwork/charon/core"
)

var (
	broadcastCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "bcast",
		Name:      "broadcast_total",
		Help:      "The total count of successfully broadcast duties by type",
	}, []string{"duty"})

	broadcastDelay = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "core",
		Subsystem: "bcast",
		Name:      "broadcast_delay_seconds",
		Help:      "Duty broadcast delay from start of slot in seconds by type",
		Buckets:   []float64{.05, .1, .25, .5, 1, 2.5, 5, 10, 20, 30, 60},
	}, []string{"duty"})

	recastRegistrationCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "bcast",
		Name:      "recast_registration_total",
		Help:      "The total number of unique validator registration stored in recaster per pubkey",
	}, []string{"pubkey"})

	recastTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "bcast",
		Name:      "recast_total",
		Help:      "The total count of recasted registrations by type; 'pregen' vs 'vc'",
	}, []string{"type"})

	recastErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "bcast",
		Name:      "recast_errors_total",
		Help:      "The total count of failed recasted registrations by type; 'pregen' vs 'vc'",
	}, []string{"type"})
)

// instrumentDuty increments the duty counter.
func instrumentDuty(duty core.Duty, delay time.Duration) {
	broadcastCounter.WithLabelValues(duty.Type.String()).Inc()
	broadcastDelay.WithLabelValues(duty.Type.String()).Observe(delay.Seconds())
}
