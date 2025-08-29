// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package sse

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

var (
	sseHeadSlotGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "app",
		Subsystem: "beacon_node",
		Name:      "sse_head_slot",
		Help:      "Current beacon node head slot, supplied by beacon node's SSE endpoint",
	}, []string{"addr"})

	sseHeadDelayHistogram = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "app",
		Subsystem: "beacon_node",
		Name:      "sse_head_delay",
		Help:      "Delay in seconds between slot start and head update, supplied by beacon node's SSE endpoint. Values between 8s and 12s for Ethereum mainnet are considered safe.",
		Buckets:   []float64{2, 4, 6, 8, 10, 12},
	}, []string{"addr"})

	sseChainReorgDepthHistogram = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "app",
		Subsystem: "beacon_node",
		Name:      "sse_chain_reorg_depth",
		Help:      "Chain reorg depth, supplied by beacon node's SSE endpoint",
		Buckets:   []float64{1, 2, 4, 6, 8, 16},
	}, []string{"addr"})

	sseBlockGossipHistogram = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "app",
		Subsystem: "beacon_node",
		Name:      "sse_block_gossip",
		Help:      "Block reception via gossip delay, supplied by beacon node's SSE endpoint. Values between 0s and 4s for Ethereum mainnet are considered safe",
		Buckets:   []float64{0.5, 1, 1.5, 2, 2.5, 3, 3.5, 4, 4.5, 5, 6, 8, 10, 12},
	}, []string{"addr"})

	sseBlockHistogram = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "app",
		Subsystem: "beacon_node",
		Name:      "sse_block",
		Help:      "Block imported into fork choice delay, supplied by beacon node's SSE endpoint. Values between 0s and 4s for Ethereum mainnet are considered safe",
		Buckets:   []float64{0.5, 1, 1.5, 2, 2.5, 3, 3.5, 4, 4.5, 5, 6, 8, 10, 12},
	}, []string{"addr"})
)
