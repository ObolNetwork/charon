// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package fetcher

import (
	"math/big"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
	"github.com/obolnetwork/charon/eth2util"
)

var proposalBlindedGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: "core",
	Subsystem: "fetcher",
	Name:      "proposal_blinded",
	Help:      "Whether the fetched proposal was built by a builder via p2p (1, blinded pre-gloas), locally (2) or by a direct builder (3), labelled by builder host when direct",
}, []string{"builder"})

// Values of proposalBlindedGauge: a builder-built proposal travels without its execution
// payload (a blinded proposal pre-gloas, a payload-excluded builder bid from gloas
// onwards), a locally built one carries it. From gloas a direct builder's bid, one the
// beacon node requested from a configured builder, is told apart from a p2p bid.
const (
	proposalSourceBuilder = float64(1)
	proposalSourceLocal   = float64(2)
	proposalSourceDirect  = float64(3)
)

// proposalValueSum and proposalValueCount add up the values of fetched gloas proposals exactly, so
// their increase over a window gives the exact average value, or the value of a lone proposal.
var (
	proposalValueSum = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "fetcher",
		Name:      "proposal_value_gwei_total",
		Help:      "Sum of the values of fetched gloas proposals in gwei by type: the builder bid value (builder bids only), the execution payload value and the consensus block value (when known)",
	}, []string{"type"})

	proposalValueCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "fetcher",
		Name:      "proposal_values_total",
		Help:      "Number of values of fetched gloas proposals added to core_fetcher_proposal_value_gwei_total by type",
	}, []string{"type"})
)

// Types of proposalValueSum and proposalValueCount.
const (
	proposalValueBid       = "bid"
	proposalValueExecution = "execution"
	proposalValueConsensus = "consensus"
)

// weiPerGwei converts wei values to gwei.
var weiPerGwei = big.NewFloat(1e9)

// addProposalValue adds a gwei value of a fetched proposal.
func addProposalValue(typ string, gwei float64) {
	proposalValueSum.WithLabelValues(typ).Add(gwei)
	proposalValueCount.WithLabelValues(typ).Inc()
}

// addProposalWeiValue adds a wei value of a fetched proposal in gwei, if known.
func addProposalWeiValue(typ string, wei *big.Int) {
	if wei == nil {
		return
	}

	gwei, _ := new(big.Float).Quo(new(big.Float).SetInt(wei), weiPerGwei).Float64()
	addProposalValue(typ, gwei)
}

// maxBuilderLabelLen caps the builder label value at the maximum length of a hostname.
const maxBuilderLabelLen = 253

// setProposalSource sets proposalBlindedGauge as its only series, so the label of an earlier
// proposal's builder doesn't linger.
func setProposalSource(source float64, builderURL string) {
	proposalBlindedGauge.Reset()
	proposalBlindedGauge.WithLabelValues(builderLabel(builderURL)).Set(source)
}

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

var proposalLocalMismatchFeeRecipientGauge = promauto.NewGauge(prometheus.GaugeOpts{
	Namespace: "core",
	Subsystem: "fetcher",
	Name:      "proposal_local_mismatch_fee_recipient",
	Help:      "Counts the number of times a local proposal has a mismatched fee recipient",
})
