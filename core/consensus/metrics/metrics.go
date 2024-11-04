// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

var (
	decidedRoundsGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "core",
		Subsystem: "consensus",
		Name:      "decided_rounds",
		Help:      "Number of decided rounds by protocol, duty, and timer",
	}, []string{"protocol", "duty", "timer"})

	decidedLeaderGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "core",
		Subsystem: "consensus",
		Name:      "decided_leader_index",
		Help:      "Index of the decided leader by protocol and duty",
	}, []string{"protocol", "duty"})

	consensusDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "core",
		Subsystem: "consensus",
		Name:      "duration_seconds",
		Help:      "Duration of the consensus process by protocol, duty, and timer",
	}, []string{"protocol", "duty", "timer"})

	consensusTimeout = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "consensus",
		Name:      "timeout_total",
		Help:      "Total count of consensus timeouts by protocol, duty, and timer",
	}, []string{"protocol", "duty", "timer"})

	consensusError = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "consensus",
		Name:      "error_total",
		Help:      "Total count of consensus errors by protocol",
	}, []string{"protocol"})
)

// ConsensusMetrics defines the interface for consensus metrics.
type ConsensusMetrics interface {
	// SetDecidedRounds sets the number of decided rounds for a given duty and timer.
	SetDecidedRounds(duty, timer string, rounds int64)

	// SetDecidedLeaderIndex sets the decided leader index for a given duty.
	SetDecidedLeaderIndex(duty string, leaderIndex int64)

	// ObserveConsensusDuration observes the duration of the consensus process for a given duty and timer.
	ObserveConsensusDuration(duty, timer string, duration float64)

	// IncConsensusTimeout increments the consensus timeout counter for a given duty and timer.
	IncConsensusTimeout(duty, timer string)

	// IncConsensusError increments the consensus error counter.
	IncConsensusError()
}

type consensusMetrics struct {
	protocolID string
}

// NewConsensusMetrics creates a new instance of ConsensusMetrics with the given protocol ID.
func NewConsensusMetrics(protocolID string) ConsensusMetrics {
	return &consensusMetrics{
		protocolID: protocolID,
	}
}

// SetDecidedRounds sets the number of decided rounds for a given duty and timer.
func (m *consensusMetrics) SetDecidedRounds(duty, timer string, rounds int64) {
	decidedRoundsGauge.WithLabelValues(m.protocolID, duty, timer).Set(float64(rounds))
}

// SetDecidedLeaderIndex sets the decided leader index for a given duty.
func (m *consensusMetrics) SetDecidedLeaderIndex(duty string, leaderIndex int64) {
	decidedLeaderGauge.WithLabelValues(m.protocolID, duty).Set(float64(leaderIndex))
}

// ObserveConsensusDuration observes the duration of the consensus process for a given duty and timer.
func (m *consensusMetrics) ObserveConsensusDuration(duty, timer string, duration float64) {
	consensusDuration.WithLabelValues(m.protocolID, duty, timer).Observe(duration)
}

// IncConsensusTimeout increments the consensus timeout counter for a given duty and timer.
func (m *consensusMetrics) IncConsensusTimeout(duty, timer string) {
	consensusTimeout.WithLabelValues(m.protocolID, duty, timer).Inc()
}

// IncConsensusError increments the consensus error counter.
func (m *consensusMetrics) IncConsensusError() {
	consensusError.WithLabelValues(m.protocolID).Inc()
}
