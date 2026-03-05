// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package sigagg

//go:generate go test . -run=TestMetricReference -update-markdown

// MetricReference contains metadata about sigagg metrics for documentation generation.
type MetricReference struct {
	Name   string
	Type   string
	Help   string
	Labels string
}

// SigAggMetrics returns the list of metrics exposed by this package.
func SigAggMetrics() []MetricReference {
	return []MetricReference{
		{
			Name:   "core_sigagg_slot_aggregation_seconds",
			Type:   "Histogram",
			Help:   "Total duration to aggregate all validators for a duty in a slot, in seconds",
			Labels: "duty",
		},
	}
}
