// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package parsigdb

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

var exitCounter = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "core",
	Subsystem: "parsigdb",
	Name:      "exit_total",
	Help:      "Total number of partially signed voluntary exits per public key",
}, []string{"pubkey"}) // Ok to use pubkey (high cardinality) here since these are very rare

var parsigStored = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Namespace: "core",
	Subsystem: "parsigdb",
	Name:      "store",
	Help:      "Latency of partial signatures received since earliest expected time, per duty, per peer index",
	Buckets:   []float64{.001, 0.01, 0.05, .1, .25, .5, .75, 1, 1.25, 1.5, 1.75, 2.0, 2.25, 2.5, 2.75, 3, 5},
}, []string{"duty", "peer_idx"})
