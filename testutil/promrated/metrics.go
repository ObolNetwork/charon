// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package promrated

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

var (
	validatorLabels = []string{"pubkey_full", "cluster_name", "cluster_hash", "cluster_network"}
	networkLabels   = []string{"cluster_network"}

	uptime = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "promrated",
		Name:      "validator_uptime",
		Help:      "Uptime of a validation key.",
	}, validatorLabels)

	correctness = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "promrated",
		Name:      "validator_correctness",
		Help:      "Average correctness of a validation key.",
	}, validatorLabels)

	inclusionDelay = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "promrated",
		Name:      "validator_inclusion_delay",
		Help:      "Average inclusion delay of a validation key.",
	}, validatorLabels)

	attester = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "promrated",
		Name:      "validator_attester_effectiveness",
		Help:      "Attester effectiveness of a validation key.",
	}, validatorLabels)

	proposer = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "promrated",
		Name:      "validator_proposer_effectiveness",
		Help:      "Proposer effectiveness of a validation key.",
	}, validatorLabels)

	effectiveness = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "promrated",
		Name:      "validator_effectiveness",
		Help:      "Effectiveness of a validation key.",
	}, validatorLabels)

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
