// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package sse

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

var (
	sseHeadGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "app",
		Subsystem: "beacon_node",
		Name:      "sse_head",
		Help:      "Current beacon node head slot, supplied by beacon node's SSE endpoint",
	}, []string{"addr", "block"})

	sseHeadDelayHistogram = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "app",
		Subsystem: "beacon_node",
		Name:      "sse_head_delay",
		Help:      "Delay in seconds between slot start and head update, supplied by beacon node's SSE endpoint. Values between 8s and 12s for Ethereum mainnet are considered safe.",
	}, []string{"addr"})

	sseChainReorgDepthGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "app",
		Subsystem: "beacon_node",
		Name:      "sse_chain_reorg_depth",
		Help:      "Chain reorg depth, supplied by beacon node's SSE endpoint",
	}, []string{"addr"})
)
