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
		Name: "beacon_node_syncing",
		Description: `Beacon Node in syncing state. It should resolve within an hour. While it is syncing it won't be able to perform any duties.
		If it doesn't resolve, check the beacon node's peer count; a healthy beacon node should have at least 30 peers.
		If it does have enough peers, usually a restart fixes it.
		If it doesn't, wiping the beacon node's DB might be required.
		In any case, first inspect the beacon node logs for more details, as they usually give more context.`,
		Severity: severityCritical,
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
		Description: "Not connected to at least quorum peers. Check logs for networking issues or coordinate with peers.",
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
		Description: "Metrics have reached the high cardinality threshold. Please check metrics reported by app_health_metrics_high_cardinality.",
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
		Name: "high_beacon_node_latency",
		Description: `Beacon node requests latency exceeds 1s.
		Note that proposal and submit_proposal endpoints are excluded from this check as they have a higher threshold.

		The panel Beacon Node API request latency should be checked for more details on which endpoints are affected.
		Slow *_duties requests will affect scheduling of duties and potentially lead to missed proposal duties during the first slot of the epoch.
		Slow data requests (attestation_data, aggregate_attestations, sync_committee_contribution) may cause a leader missing its participation. In scenarios of chain_split_halt, slow attestation_data will slow down the signing for the node.
		Slow submit_* requests are not as critical as the rest, as at least 1 peer is enough to submit them on time.
		Slow validators requests may miss some freshly activated validators.
		Any other endpoints are not as crucial, but still should be taken into consideration.

		Check if the node isn't under too much load (multiple Charons speaking to it) or if it's underprovisioned for the current load (usually memory).`,
		Severity: severityWarning,
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
		Name: "high_beacon_node_proposal_latency",
		Description: `Beacon node proposal and submit_proposal requests latency exceeds 2s.
		proposal endpoint is expected to be satisfied in ~1000ms (±100ms), anything above that signals a problem, usually related to the MEV connected to the beacon node.
		Usually those issues are:
		- one relay being slow to respond or erroring, causing the BN to wait the maximum amount of time of 950ms;
		- submit_validator_registrations request being processed and slow to respond;
		- connectivity between MEV and beacon node being slow.
		Those may force the beacon node to create a local block, which takes more time.

		submit_proposal endpoint is usually slow if the MEV relay is slow to unblind the payload. Not as critical, as at least 1 peer is enough to submit the proposal on time.

		Check if the MEV isn't misconfigured. By checking MEV logs, usually the faulty relay can be identified.`,
		Severity: severityWarning,
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
		Name: "high_peer_clock_offset",
		Description: `Peer clock offset exceeds 200ms.
		Clock offset is the difference between the local clock and the peer's clock. High clock offset can cause mismatches in peers' perspective of when a round starts and when it times out.
		The higher the clock offset, the more likely it is to cause issues in consensus and duty execution.

		This is a severe hardware related issue. Usually a machine restart helps (not only Charon, but the whole machine).
		If it doesn't, moving Charon to another machine (potentially with different geolocation) is recommended.`,
		Severity: severityWarning,
		Func: func(q query, _ Metadata) (bool, error) {
			maxAbs, err := q("app_peerinfo_clock_offset_seconds", maxAbsGaugeLabels, gaugeMax)
			if err != nil {
				return false, err
			}

			return maxAbs > 0.2, nil // 200ms threshold
		},
	},
	{
		Name: "high_peer_ping_latency",
		Description: `High peer ping latency detected (>150ms).
		Ping latency is the time it takes for a message to travel from the local node to a peer and back.

		Ensuring there is direct connection between the nodes is a first step to improve the latency (Public IP required).
		Bringing nodes closer together (e.g. same continent) or increasing the available bandwidth can help reduce latency as well.`,
		Severity: severityWarning,
		Func: func(q query, _ Metadata) (bool, error) {
			maxAvg, err := q("p2p_ping_latency_secs", histogramMaxAvg, gaugeMax)
			if err != nil {
				return false, err
			}

			return maxAvg > 0.15, nil // 150ms threshold
		},
	},
	{
		Name: "using_fallback_beacon_nodes",
		Description: `Using fallback beacon nodes instead of main beacon node(s).
		In a healthy setup, fallback beacon nodes should not be used, as requests to them are triggered only after the ones to the main nodes fail.
		This implies that a timeout has likely already occurred and the request is sent later than it should be to the fallback nodes.

		Check the health of the main beacon node(s).`,
		Severity: severityWarning,
		Func: func(q query, _ Metadata) (bool, error) {
			maxVal, err := q("app_eth2_using_fallback", sumLabels(), gaugeMax)
			if err != nil {
				return false, err
			}

			return maxVal > 0, nil
		},
	},
	{
		Name: "high_consensus_rounds",
		Description: `Consensus required >=2 rounds for proposer or attester duty.
		This usually indicates some other underlying issue like poor peer connectivity or slow connection to the beacon node.
		It may also be an expected event — if a peer restarted its Charon, beacon node, or experienced a brief downtime.`,
		Severity: severityWarning,
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
		Name: "local_block_proposal",
		Description: `Local block proposal instead of blinded (MEV). Check MEV relay connectivity.
		This impacts proposal data being quickly exchanged between the peers, as local blocks are heavier.
		It increases the chance of missing the proposal duty, as the consensus is slower between the peers.

		Usually the issues that cause it are:
		- submit_validator_registrations request being processed and slow to respond;
		- connectivity between MEV and beacon node being slow.
		Observing MEV logs can help identify the root cause of the issue.`,
		Severity: severityWarning,
		Func: func(q query, _ Metadata) (bool, error) {
			maxVal, err := q("core_fetcher_proposal_blinded", noLabels, gaugeMax)
			if err != nil {
				return false, err
			}

			return maxVal == 2, nil // 1=blinded (MEV), 2=local block
		},
	},
	{
		Name: "high_beacon_node_sse_head_delay",
		Description: `Beacon node SSE head received after 4s for >4% of the blocks in the past hour.
		This impacts head vote accuracy in attestations.

		Check if the node isn't under too much load (multiple Charons speaking to it) or if it's underprovisioned for the current load (usually memory).
		Potentially changing the beacon node client type and/or its geolocation can help as well.`,
		Severity:    severityWarning,
		MetricsFunc: sseHeadDelayCheck,
	},
	{
		Name: "high_parsigdb_store_latency",
		Description: `Attestation partial signatures from peers are received more than 2s after the expected time on average.
		Late partial signatures may delay or miss signature aggregation, leading to failed attestations.

		Check peer connectivity and ping latency. Ensuring direct connections (public IP) and bringing nodes geographically closer can help.
		If peers are sending those partial signatures way too late, they may be erroring, check their logs. Especially if this healthcheck is failing in multiple other peers.`,
		Severity: severityWarning,
		Func: func(q query, _ Metadata) (bool, error) {
			maxAvg, err := q("core_parsigdb_store",
				histogramMaxAvgWhere([]*pb.LabelPair{l("duty", "attester")}, nil),
				gaugeMax)
			if err != nil {
				return false, err
			}

			return maxAvg > 2.0, nil // 2s threshold
		},
	},
	{
		Name:        "high_goroutine_count",
		Description: `Goroutine count exceeds 1000. Possible leak. Report to Obol technical team.`,
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
		Description: `Memory usage has grown >10% over the past 24h compared to the previous 24h. Possible memory leak. Report to Obol technical team.`,
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
