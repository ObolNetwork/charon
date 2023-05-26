// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package tracker

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

var (
	participationGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "core",
		Subsystem: "tracker",
		Name:      "participation",
		Help:      "Set to 1 if peer participated successfully for the given duty or else 0",
	}, []string{"duty", "peer"})

	// TODO(corver): Remove in v0.17 once all dashboards have been updated.
	participationSuccessLegacy = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "tracker",
		Name:      "participation_total",
		Help:      "Total number of successful participations by peer and duty type",
	}, []string{"duty", "peer"})

	participationSuccess = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "tracker",
		Name:      "participation_success_total",
		Help:      "Total number of successful participations by peer and duty type",
	}, []string{"duty", "peer"})

	participationMissed = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "tracker",
		Name:      "participation_missed_total",
		Help:      "Total number of missed participations by peer and duty type",
	}, []string{"duty", "peer"})

	participationExpect = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "tracker",
		Name:      "participation_expected_total",
		Help:      "Total number of expected participations (fail + success) by peer and duty type",
	}, []string{"duty", "peer"})

	dutyFailed = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "tracker",
		Name:      "failed_duties_total",
		Help:      "Total number of failed duties by type",
	}, []string{"duty"})

	// dutyFailedReasons is separate from dutyFailed since we do not want to initialise this
	// with all failed reasons since cardinality too high.
	dutyFailedReasons = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "tracker",
		Name:      "failed_duty reasons_total",
		Help:      "Total number of failed duties by type and reason code",
	}, []string{"duty", "reason"})

	dutySuccess = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "tracker",
		Name:      "success_duties_total",
		Help:      "Total number of successful duties by type",
	}, []string{"duty"})

	dutyExpect = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "tracker",
		Name:      "expect_duties_total",
		Help:      "Total number of expected duties (failed + success) by type",
	}, []string{"duty"})

	unexpectedEventsCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "tracker",
		Name:      "unexpected_events_total",
		Help:      "Total number of unexpected events by peer",
	}, []string{"peer"})

	inconsistentCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "tracker",
		Name:      "inconsistent_parsigs_total",
		Help:      "Total number of duties that contained inconsistent partial signed data by duty type",
	}, []string{"duty"})

	inclusionDelay = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "core",
		Subsystem: "tracker",
		Name:      "inclusion_delay",
		Help:      "Cluster's average attestation inclusion delay in slots",
	})

	inclusionMisses = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "tracker",
		Name:      "inclusion_missed_total",
		Help:      "Total number of broadcast duties never included in any block by type",
	}, []string{"duty"})
)
