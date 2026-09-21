// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"crypto/sha256"
	"fmt"
	"slices"
)

// builderConfigured returns true if builder URLs are configured, enabling the v2
// proposer configuration output. The other builder flags are rejected without URLs,
// so they cannot be set (and silently dropped) on their own.
func builderConfigured(conf Config) bool {
	return len(conf.BuilderURLs) > 0
}

// builderConfigHash returns a digest of the canonicalised builder configuration.
// It is exchanged via the peerinfo protocol so peers can detect divergent builder
// configurations, which would produce divergent (non-aggregatable) builder duties.
func builderConfigHash(conf Config) []byte {
	urls := slices.Clone(conf.BuilderURLs)
	slices.Sort(urls)

	h := sha256.New()
	_, _ = h.Write([]byte("charon/builder_config/v1\n"))

	for _, u := range urls {
		_, _ = fmt.Fprintf(h, "url:%s\n", u)
	}

	_, _ = fmt.Fprintf(h, "min_bid:%d\nbuilder_boost_factor:%d\nmax_execution_payment:%d\n",
		conf.BuilderMinBid, conf.BuilderBoostFactor, conf.BuilderMaxExecutionPayment)

	return h.Sum(nil)
}

// initBuilderConfigMetrics sets the builder config gauges to this node's builder
// configuration so central monitoring can compare the values across the cluster nodes.
func initBuilderConfigMetrics(conf Config) {
	if !builderConfigured(conf) {
		return
	}

	for _, u := range conf.BuilderURLs {
		builderURLGauge.WithLabelValues(u).Set(1)
	}

	builderMinBidGauge.WithLabelValues().Set(float64(conf.BuilderMinBid))
	builderBoostFactorGauge.WithLabelValues().Set(float64(conf.BuilderBoostFactor))
	builderMaxExecutionPaymentGauge.WithLabelValues().Set(float64(conf.BuilderMaxExecutionPayment))
}
