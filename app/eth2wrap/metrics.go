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

	forkReadinessGauge = promauto.NewResetGaugeVec(prometheus.GaugeOpts{
		Namespace: "app",
		Subsystem: "fork",
		Name:      "readiness",
		Help:      "Constant gauge set to 1 per fork and component with the fork readiness status: ready, upgrade_required, known_issues or unknown. The address label is set for per-beacon-node rows",
	}, []string{"fork", "component", "status", "address"})

	invalidatedCacheDueReorgCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "app",
		Subsystem: "cache",
		Name:      "invalidated_reorg_total",
		Help:      "Total number of times the cache was invalidated due to a chain reorg",
	}, []string{"endpoint"})
)
