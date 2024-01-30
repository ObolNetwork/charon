// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
