// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"net/url"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/cluster/proposerconfig"
)

// initBuilderConfigMetrics sets the builder config gauges to this node's builder configuration so central
// monitoring can compare the values across the cluster nodes. It first clears previously set gauges, which
// are absent when no builder is configured.
func initBuilderConfigMetrics(b *proposerconfig.Builder) {
	builderURLGauge.Reset()
	builderMinBidGauge.Reset()
	builderBoostFactorGauge.Reset()
	builderMaxExecutionPaymentGauge.Reset()

	if b == nil || len(b.Builders) == 0 {
		return
	}

	for _, entry := range b.Builders {
		builderURLGauge.WithLabelValues(withoutUserInfo(entry.URL)).Set(1)
	}

	setGauge := func(g *prometheus.GaugeVec, value string) {
		v, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return // Validated when the document is loaded.
		}

		g.WithLabelValues().Set(float64(v))
	}

	setGauge(builderMinBidGauge, b.MinBid)
	setGauge(builderBoostFactorGauge, b.BuilderBoostFactor)
	setGauge(builderMaxExecutionPaymentGauge, b.MaxExecutionPayment)
}

// withoutUserInfo returns the URL without its user info. Relay URLs carry the relay's public key as the
// username, which only lengthens the label, and private builders may carry a password.
func withoutUserInfo(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}

	u.User = nil

	return u.String()
}
