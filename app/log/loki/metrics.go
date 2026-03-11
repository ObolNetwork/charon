// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package loki

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

var droppedTotal = promauto.NewCounter(prometheus.CounterOpts{
	Namespace: "app",
	Subsystem: "log_loki",
	Name:      "dropped_total",
	Help:      "Total count of dropped log lines due to full buffer",
})
