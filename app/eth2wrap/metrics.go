// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

var (
	usedCacheCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "app",
		Subsystem: "cache",
		Name:      "hits_total",
		Help:      "Total number of times the cache was used",
	}, []string{"endpoint"})

	missedCacheCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "app",
		Subsystem: "cache",
		Name:      "misses_total",
		Help:      "Total number of times the cache was missed",
	}, []string{"endpoint"})

	invalidatedCacheDueReorgCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "app",
		Subsystem: "cache",
		Name:      "invalidated_reorg_total",
		Help:      "Total number of times the cache was invalidated due to a chain reorg",
	}, []string{"endpoint"})
)
