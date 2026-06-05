// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package validatorapi

import (
	"strconv"
	"strings"
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

	proxyAPILatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "core",
		Subsystem: "validatorapi",
		Name:      "proxy_request_latency_seconds",
		Help:      "The validatorapi proxy request latencies in seconds by path",
	}, []string{"path"})

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

func observeProxyAPILatency(path string) func() {
	t0 := time.Now()

	label := proxyPathLabel(path)

	return func() {
		proxyAPILatency.WithLabelValues(label).Observe(time.Since(t0).Seconds())
	}
}

// proxyPathLabel converts a request path into a bounded metric label by replacing dynamic
// path segments with placeholders. Without this, paths like /eth/v2/beacon/blocks/0x<root>
// produce a unique label value per block root, which grows metric cardinality (and memory)
// without bound.
func proxyPathLabel(path string) string {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	for i, segment := range segments {
		switch {
		case strings.HasPrefix(segment, "0x"):
			segments[i] = "{hex}" // Block/state roots, validator pubkeys.
		case isNumeric(segment):
			segments[i] = "{n}" // Slots, epochs, validator indices.
		case i > 0 && segments[i-1] == "peers":
			segments[i] = "{peer_id}" // libp2p peer IDs are base58/base32, not hex or numeric.
		default:
		}
	}

	return strings.Join(segments, "_")
}

// isNumeric returns true if s is non-empty and contains only ASCII digits.
func isNumeric(s string) bool {
	if s == "" {
		return false
	}

	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}

	return true
}
