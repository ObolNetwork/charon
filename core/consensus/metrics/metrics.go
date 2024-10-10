// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

type ConsensusMetrics interface {
	SetDecidedRounds(duty, timer string, rounds float64)
	ObserveConsensusDuration(duty, timer string, duration float64)
	IncConsensusTimeout(duty, timer string)
	IncConsensusError()
}

var (
	decidedRoundsGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "core",
		Subsystem: "consensus",
		Name:      "decided_rounds",
		Help:      "Number of rounds it took to decide consensus instances by duty and timer type.",
	}, []string{"protocol", "duty", "timer"}) // Using gauge since the value changes slowly, once per slot.

	consensusDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "core",
		Subsystem: "consensus",
		Name:      "duration_seconds",
		Help:      "Duration of a consensus instance in seconds by duty and timer type.",
		Buckets:   []float64{.05, .1, .25, .5, 1, 2.5, 5, 10, 20, 30, 60},
	}, []string{"protocol", "duty", "timer"})

	consensusTimeout = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "consensus",
		Name:      "timeout_total",
		Help:      "Total count of consensus timeouts by duty and timer type.",
	}, []string{"protocol", "duty", "timer"})

	consensusError = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "consensus",
		Name:      "error_total",
		Help:      "Total count of consensus errors",
	}, []string{"protocol"})
)

type consensusMetrics struct {
	protocolID string
}

func NewConsensusMetrics(protocolID string) ConsensusMetrics {
	return &consensusMetrics{
		protocolID: protocolID,
	}
}

func (m *consensusMetrics) SetDecidedRounds(duty, timer string, rounds float64) {
	decidedRoundsGauge.WithLabelValues(m.protocolID, duty, timer).Set(rounds)
}

func (m *consensusMetrics) ObserveConsensusDuration(duty, timer string, duration float64) {
	consensusDuration.WithLabelValues(m.protocolID, duty, timer).Observe(duration)
}

func (m *consensusMetrics) IncConsensusTimeout(duty, timer string) {
	consensusTimeout.WithLabelValues(m.protocolID, duty, timer).Inc()
}

func (m *consensusMetrics) IncConsensusError() {
	consensusError.WithLabelValues(m.protocolID).Inc()
}
