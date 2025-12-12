// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package fetcher

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

var proposalBlindedGauge = promauto.NewGauge(prometheus.GaugeOpts{
	Namespace: "core",
	Subsystem: "fetcher",
	Name:      "proposal_blinded",
	Help:      "Whether the fetched proposal was blinded (1) or local (2)",
})
