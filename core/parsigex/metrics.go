// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package parsigex

//go:generate go test . -run=TestMetricReference -update-markdown

// MetricReference contains metadata about parsigex metrics for documentation generation.
type MetricReference struct {
	Name   string
	Type   string
	Help   string
	Labels string
}

// ParSigExMetrics returns the list of metrics exposed by this package.
func ParSigExMetrics() []MetricReference {
	return []MetricReference{
		{
			Name:   "core_parsigex_set_verification_seconds",
			Type:   "Histogram",
			Help:   "Duration to verify all partial signatures in a received set, in seconds",
			Labels: "duty",
		},
	}
}
