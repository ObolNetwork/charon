// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package health

import (
	pb "github.com/prometheus/client_model/go"
)

// severity is the severity of a health check.
type severity string

const (
	severityCritical severity = "critical"
	severityWarning  severity = "warning"
	severityInfo     severity = "info"
)

// Metadata contains metadata about the charon cluster.
type Metadata struct {
	NumValidators int
	NumPeers      int
	QuorumPeers   int
}

// check is a health check.
type check struct {
	// Name of the health check.
	Name string
	// Description of the health check.
	Description string
	// Severity of the health check.
	Severity severity
	// Func returns true if the health check is failing, false otherwise.
	// Exactly one of Func, MemFunc, or MetricsFunc must be set.
	Func func(query, Metadata) (bool, error)
	// MemFunc is used for checks that need access to the long-term memory snapshot buffer.
	// Exactly one of Func, MemFunc, or MetricsFunc must be set.
	MemFunc func([]memorySnapshot, Metadata) (bool, error)
	// MetricsFunc is used for checks that need access to the raw scrape history,
	// e.g. to compute rates across the scrape window.
	// Exactly one of Func, MemFunc, or MetricsFunc must be set.
	MetricsFunc func([][]*pb.MetricFamily, Metadata) (bool, error)
}

// query abstracts the function to query the metric store returning a value by reducing the selected time series for a given metric name.
type query func(name string, selector labelSelector, reducer seriesReducer) (float64, error)

// checks is a list of health checks.
var checks = []check{
	{
		Name:        "high_error_log_rate",
		Description: "High rate of error logs. Please check the logs for more details.",
		Severity:    severityWarning,
		Func: func(q query, m Metadata) (bool, error) {
			increase, err := q("app_log_error_total", sumLabels(), increase)
			if err != nil {
				return false, err
			}

			return increase > 2*float64(m.NumValidators), nil // Allow 2 errors per validator.
		},
	},
	{
		Name:        "high_warning_log_rate",
		Description: "High rate of warning logs. Please check the logs for more details.",
		Severity:    severityWarning,
		Func: func(q query, m Metadata) (bool, error) {
			increase, err := q("app_log_warning_total", sumLabels(), increase)
			if err != nil {
				return false, err
			}

			return increase > 2*float64(m.NumValidators), nil // Allow 2 warnings per validator.
		},
	},
	{
		Name:        "beacon_node_syncing",
		Description: "Beacon Node in syncing state.",
		Severity:    severityCritical,
		Func: func(q query, _ Metadata) (bool, error) {
			maxVal, err := q("app_monitoring_beacon_node_syncing", noLabels, gaugeMax)
			if err != nil {
				return false, err
			}

			return maxVal == 1, nil
		},
	},
	{
		Name:        "insufficient_connected_peers",
		Description: "Not connected to at least quorum peers. Check logs for networking issue or coordinate with peers.",
		Severity:    severityCritical,
		Func: func(q query, m Metadata) (bool, error) {
			maxVal, err := q("p2p_ping_success", countNonZeroLabels, gaugeMax)
			if err != nil {
				return false, err
			}

			required := float64(m.QuorumPeers) - 1 // Exclude self

			return maxVal < required, nil
		},
	},
	{
		Name:        "pending_validators",
		Description: "Pending validators detected. Activate them to start validating.",
		Severity:    severityInfo,
		Func: func(q query, _ Metadata) (bool, error) {
			maxVal, err := q("core_scheduler_validator_status",
				countLabels(l("status", "pending")),
				gaugeMax)
			if err != nil {
				return false, err
			}

			return maxVal > 0, nil
		},
	},
	{
		Name:        "proposal_failures",
		Description: "Proposal failures detected. See <link to troubleshoot proposal failures>.",
		Severity:    severityWarning,
		Func: func(q query, _ Metadata) (bool, error) {
			increase, err := q("core_tracker_failed_duties_total",
				sumLabels(l("duty", ".*proposal")), increase)
			if err != nil {
				return false, err
			}

			return increase > 0, nil
		},
	},
	{
		Name:        "high_registration_failures_rate",
		Description: "High rate of failed validator registrations. Please check the logs for more details.",
		Severity:    severityWarning,
		Func: func(q query, _ Metadata) (bool, error) {
			increase, err := q("core_scheduler_submit_registration_errors_total", sumLabels(), increase)
			if err != nil {
				return false, err
			}

			return increase > 0, nil
		},
	},
	{
		Name:        "metrics_high_cardinality",
		Description: "Metrics reached high cardinality threshold. Please check metrics reported by app_health_metrics_high_cardinality.",
		Severity:    severityWarning,
		Func: func(q query, _ Metadata) (bool, error) {
			maxVal, err := q("app_health_metrics_high_cardinality", sumLabels(), gaugeMax)
			if err != nil {
				return false, err
			}

			return maxVal > 0, nil
		},
	},
	{
		Name:        "high_beacon_node_latency",
		Description: "Beacon node API latency exceeds 1s. Check beacon node performance.",
		Severity:    severityWarning,
		Func: func(q query, _ Metadata) (bool, error) {
			// Exclude proposal endpoints which have a higher threshold (see high_beacon_node_proposal_latency).
			maxAvg, err := q("app_eth2_latency_seconds",
				histogramMaxAvgWhere(nil, []*pb.LabelPair{l("endpoint", "^(proposal|submit_blinded_proposal)$")}),
				gaugeMax)
			if err != nil {
				return false, err
			}

			return maxAvg > 1.0, nil
		},
	},
	{
		Name:        "high_beacon_node_proposal_latency",
		Description: "Beacon node proposal API latency exceeds 2s. Check beacon node performance.",
		Severity:    severityWarning,
		Func: func(q query, _ Metadata) (bool, error) {
			maxAvg, err := q("app_eth2_latency_seconds",
				histogramMaxAvgWhere([]*pb.LabelPair{l("endpoint", "^(proposal|submit_blinded_proposal)$")}, nil),
				gaugeMax)
			if err != nil {
				return false, err
			}

			// Includes also calls to MEV, so we do expect to go above 1s.
			return maxAvg > 2.0, nil
		},
	},
	{
		Name:        "high_peer_clock_offset",
		Description: "Peer clock offset exceeds 200ms. Check NTP synchronization on affected nodes.",
		Severity:    severityWarning,
		Func: func(q query, _ Metadata) (bool, error) {
			maxAbs, err := q("app_peerinfo_clock_offset_seconds", maxAbsGaugeLabels, gaugeMax)
			if err != nil {
				return false, err
			}

			return maxAbs > 0.2, nil // 200ms threshold
		},
	},
	{
		Name:        "high_peer_ping_latency",
		Description: "High peer ping latency detected (>150ms). Check network conditions between peers.",
		Severity:    severityWarning,
		Func: func(q query, _ Metadata) (bool, error) {
			maxAvg, err := q("p2p_ping_latency_secs", histogramMaxAvg, gaugeMax)
			if err != nil {
				return false, err
			}

			return maxAvg > 0.15, nil // 150ms threshold
		},
	},
	{
		Name:        "using_fallback_beacon_nodes",
		Description: "Using fallback beacon nodes. Please check primary beacon nodes health.",
		Severity:    severityWarning,
		Func: func(q query, _ Metadata) (bool, error) {
			maxVal, err := q("app_eth2_using_fallback", sumLabels(), gaugeMax)
			if err != nil {
				return false, err
			}

			return maxVal > 0, nil
		},
	},
	{
		Name:        "high_consensus_rounds",
		Description: "Consensus required >=2 rounds for proposer or attester duty. Check for peer connectivity or performance issues.",
		Severity:    severityWarning,
		Func: func(q query, _ Metadata) (bool, error) {
			maxVal, err := q("core_consensus_decided_rounds",
				maxGaugeWhere([]*pb.LabelPair{l("duty", "^(proposer|attester)$")}),
				gaugeMax)
			if err != nil {
				return false, err
			}

			return maxVal >= 2, nil
		},
	},
	{
		Name:        "local_block_proposal",
		Description: "Local block proposal detected instead of blinded (MEV). Check MEV relay connectivity.",
		Severity:    severityWarning,
		Func: func(q query, _ Metadata) (bool, error) {
			maxVal, err := q("core_fetcher_proposal_blinded", noLabels, gaugeMax)
			if err != nil {
				return false, err
			}

			return maxVal == 2, nil // 1=blinded (MEV), 2=local block
		},
	},
	{
		Name:        "high_beacon_node_sse_head_delay",
		Description: "Beacon node SSE head delay exceeds 4s for >4% of blocks. Check beacon node block reception performance.",
		Severity:    severityWarning,
		MetricsFunc: sseHeadDelayCheck,
	},
	{
		Name:        "high_goroutine_count",
		Description: "Goroutine count exceeds 1000. Possible goroutine leak.",
		Severity:    severityWarning,
		Func: func(q query, _ Metadata) (bool, error) {
			maxVal, err := q("go_goroutines", noLabels, gaugeMax)
			if err != nil {
				return false, err
			}

			return maxVal > 1000, nil
		},
	},
	{
		Name:        "memory_leak",
		Description: "Memory usage has grown >10% over the past 24h compared to the previous 24h. Possible memory leak.",
		Severity:    severityWarning,
		MemFunc:     memoryLeakCheck,
	},
}

// l is a concise convenience function to create a label pair.
func l(name, val string) *pb.LabelPair {
	return &pb.LabelPair{
		Name:  &name,
		Value: &val,
	}
}
