// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package log

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

var (
	errorCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "app",
		Subsystem: "log",
		Name:      "error_total",
		Help:      "Total count of logged errors by topic",
	}, []string{"topic"})

	warnCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace:   "app",
		Subsystem:   "log",
		Name:        "warn_total",
		Help:        "Total count of logged warnings by topic",
		ConstLabels: nil,
	}, []string{"topic"})
)

func incWarnCounter(ctx context.Context) {
	warnCounter.WithLabelValues(metricsTopicFromCtx(ctx)).Inc()
}

func incErrorCounter(ctx context.Context) {
	errorCounter.WithLabelValues(metricsTopicFromCtx(ctx)).Inc()
}
