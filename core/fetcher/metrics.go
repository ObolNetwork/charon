// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package fetcher

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

// TODO(dhruv): Remove the inconsistent counter code after the data has been collected.
var inconsistentAttDataCounter = promauto.NewCounter(prometheus.CounterOpts{
	Namespace: "core",
	Subsystem: "fetcher",
	Name:      "inconsistent_att_data_total",
	Help:      "Total number of inconsistent attestation data detected. Note this is expected.",
})
