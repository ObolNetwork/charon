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
		Help:      "Current beacon node head, supplied by beacon node's SSE endpoint",
	}, []string{"url"})

	sseHeadDelayHistogram = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "app",
		Subsystem: "beacon_node",
		Name:      "sse_head_delay",
		Help:      "Delay in ms between the beacon node head and the SSE head",
	}, []string{"url"})

	sseChainReorgDepthGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "app",
		Subsystem: "beacon_node",
		Name:      "sse_chain_reorg_depth",
		Help:      "Chain reorg depth, supplied by beacon node's SSE endpoint",
	}, []string{"url"})
)
