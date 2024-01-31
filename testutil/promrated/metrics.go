// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package promrated

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

const (
	clusterNetworkLabel = "cluster_network"
	nodeOperatorLabel   = "node_operator"
)

var (
	networkLabels = []string{clusterNetworkLabel, nodeOperatorLabel}

	networkUptime = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "promrated",
		Name:      "network_uptime",
		Help:      "Uptime of the network.",
	}, networkLabels)

	networkCorrectness = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "promrated",
		Name:      "network_correctness",
		Help:      "Average correctness of the network.",
	}, networkLabels)

	networkInclusionDelay = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "promrated",
		Name:      "network_inclusion_delay",
		Help:      "Average inclusion delay of the network.",
	}, networkLabels)

	networkEffectiveness = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "promrated",
		Name:      "network_effectiveness",
		Help:      "Effectiveness of the network.",
	}, networkLabels)

	ratedErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "promrated",
		Name:      "api_error_total",
		Help:      "Total number of rated api errors",
	}, []string{"peer"})
)
