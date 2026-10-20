// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package bcast

import (
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util"
)

var (
	broadcastCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "bcast",
		Name:      "broadcast_total",
		Help:      "The total count of successfully broadcast duties by type",
	}, []string{"duty"})

	broadcastDelay = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "core",
		Subsystem: "bcast",
		Name:      "broadcast_delay_seconds",
		Help:      "Duty broadcast delay since the expected duty submission in seconds by type",
		Buckets:   []float64{.05, .1, .25, .5, 1, 2.5, 5, 10, 20, 30, 60},
	}, []string{"duty"})

	builderPreferencesRejected = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "bcast",
		Name:      "builder_preferences_rejected_total",
		Help:      "The total count of builder preferences entries rejected by builder URL",
	}, []string{"builder"})

	proposalSourceCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "bcast",
		Name:      "proposal_source_total",
		Help:      "The total count of successfully broadcast gloas block proposals by builder source (local, p2p, direct) and builder host when direct",
	}, []string{"source", "builder"})
)

// maxBuilderLabelLen caps the builder label value at the maximum length of a hostname.
const maxBuilderLabelLen = 253

// builderLabel returns the host of a builder URL as a metric label value, empty without a URL.
func builderLabel(builderURL string) string {
	if builderURL == "" {
		return ""
	}

	host, err := eth2util.BuilderAuthData(builderURL)
	if err != nil {
		return "unknown"
	}

	label := string(host)
	if len(label) > maxBuilderLabelLen {
		label = label[:maxBuilderLabelLen]
	}

	return strings.ToValidUTF8(label, "")
}

// instrumentDuty increments the duty counter.
func instrumentDuty(duty core.Duty, delay time.Duration) {
	broadcastCounter.WithLabelValues(duty.Type.String()).Inc()
	broadcastDelay.WithLabelValues(duty.Type.String()).Observe(delay.Seconds())
}
