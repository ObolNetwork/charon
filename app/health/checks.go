// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package health

import pb "github.com/prometheus/client_model/go"

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
	Func func(query, Metadata) (bool, error)
}

// query abstracts the function to query the metric store returning a selected time series for a given metric name.
type query func(name string, selector labelSelector) ([]*pb.Metric, error)

// checks is a list of health checks.
var checks = []check{
	{
		Name:        "error_logs",
		Description: "Error logs detected that require human intervention.",
		Severity:    severityCritical,
		Func: func(q query, _ Metadata) (bool, error) {
			counts, err := q("app_log_error_total", noLabels)
			if err != nil {
				return false, err
			}

			increase, err := counterIncrease(counts)
			if err != nil {
				return false, err
			}

			return increase > 0, nil
		},
	},
	{
		Name:        "high_warning_log_rate",
		Description: "High rate of warning logs. Please check the logs for more details.",
		Severity:    severityCritical,
		Func: func(q query, m Metadata) (bool, error) {
			counts, err := q("app_log_error_total", noLabels)
			if err != nil {
				return false, err
			}

			increase, err := counterIncrease(counts)
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
		Func: func(q query, m Metadata) (bool, error) {
			gaugeVals, err := q("app_monitoring_beacon_node_syncing", noLabels)
			if err != nil {
				return false, err
			}

			max, err := gaugeMax(gaugeVals)
			if err != nil {
				return false, err
			}

			return max == 1, nil
		},
	},
	{
		Name:        "insufficient_connected_peers",
		Description: "Not connected to at least quorum peers. Check logs for networking issue or coordinate with peers.",
		Severity:    severityCritical,
		Func: func(q query, m Metadata) (bool, error) {
			counts, err := q("p2p_peer_connection_total", countNonZeroLabels)
			if err != nil {
				return false, err
			}

			min, err := gaugeMin(counts)
			if err != nil {
				return false, err
			}

			return min < float64(m.QuorumPeers), nil
		},
	},
	{
		Name:        "pending_validators",
		Description: "Pending validators detected. Activate them to start validating.",
		Severity:    severityInfo,
		Func: func(q query, m Metadata) (bool, error) {
			counts, err := q("core_scheduler_validator_status", countLabels(l("status", "pending")))
			if err != nil {
				return false, err
			}

			max, err := gaugeMax(counts)
			if err != nil {
				return false, err
			}

			return max > 0, nil
		},
	},
	{
		Name:        "proposal_failures",
		Description: "Proposal failures detected. See <link to troubleshoot proposal failures>.",
		Severity:    severityWarning,
		Func: func(q query, m Metadata) (bool, error) {
			full, err := q("core_tracker_failed_duties_total", selectLabel(l("duty", "proposal")))
			if err != nil {
				return false, err
			}

			builder, err := q("core_tracker_failed_duties_total", selectLabel(l("duty", "builder_proposal")))
			if err != nil {
				return false, err
			}

			fullIncrease, err := counterIncrease(full)
			if err != nil {
				return false, err
			}

			builderIncrease, err := counterIncrease(builder)
			if err != nil {
				return false, err
			}

			return fullIncrease+builderIncrease > 0, nil
		},
	},
}

// l is a concise convenience function to create a label pair.
func l(name, val string) *pb.LabelPair {
	return &pb.LabelPair{
		Name:  &name,
		Value: &val,
	}
}
