// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package validatorapi

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

var (
	apiLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "core",
		Subsystem: "validatorapi",
		Name:      "request_latency_seconds",
		Help:      "The validatorapi request latencies in seconds by endpoint",
	}, []string{"endpoint"})

	apiErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "validatorapi",
		Name:      "request_error_total",
		Help:      "The total number of validatorapi request errors",
	}, []string{"endpoint", "status_code"})

	vcContentType = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "validatorapi",
		Name:      "request_total",
		Help:      "The total number of requests per content-type and endpoint",
	}, []string{"endpoint", "content_type"})

	vcUserAgentGauge = promauto.NewResetGaugeVec(prometheus.GaugeOpts{
		Namespace: "core",
		Subsystem: "validatorapi",
		Name:      "vc_user_agent",
		Help:      "Gauge with label set to user agent string of requests made by VC",
	}, []string{"user_agent"})
)

func incAPIErrors(endpoint string, statusCode int) {
	apiErrors.WithLabelValues(endpoint, strconv.Itoa(statusCode)).Inc()
}

func observeAPILatency(endpoint string) func() {
	t0 := time.Now()

	return func() {
		apiLatency.WithLabelValues(endpoint).Observe(time.Since(t0).Seconds())
	}
}
