// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

var proposalLocalMismatchFeeRecipientGauge = promauto.NewGauge(prometheus.GaugeOpts{
	Namespace: "core",
	Subsystem: "fetcher",
	Name:      "proposal_local_mismatch_fee_recipient",
	Help:      "Counts the number of times a local proposal has a mismatched fee recipient",
})
