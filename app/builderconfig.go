// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"crypto/sha256"
	"fmt"
	"net/url"
	"slices"

	"github.com/attestantio/go-eth2-client/spec/gloas"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/eth2util"
)

// builderConfigured returns true if builder URLs are configured, enabling the v2
// proposer configuration output. The other builder flags are rejected without URLs,
// so they cannot be set (and silently dropped) on their own.
func builderConfigured(conf Config) bool {
	return len(conf.BuilderURLs) > 0
}

// builderConfig returns the gloas builder configuration sent as the required body of
// every v4 EPBS proposal request. MinBid and BuilderBoostFactor gate P2P builder bids
// against the locally built payload.
//
// Each configured builder is a direct builder entry without its auth: an entry requires
// the proposer's builder request auth for the proposal slot, which the fetcher adds per
// proposal from the aggregated builder preferences duty, leaving out a builder whose auth
// isn't aggregated.
func builderConfig(conf Config) *gloas.BuilderConfig {
	builders := make([]*gloas.BuilderEntry, 0, len(conf.BuilderURLs))
	for _, url := range conf.BuilderURLs {
		builders = append(builders, &gloas.BuilderEntry{
			URL:                 []byte(url),
			BuilderPubkeys:      []eth2p0.BLSPubKey{},
			MaxExecutionPayment: eth2p0.Gwei(conf.BuilderMaxExecutionPayment),
			MinBid:              eth2p0.Gwei(conf.BuilderMinBid),
			BuilderBoostFactor:  conf.BuilderBoostFactor,
		})
	}

	return &gloas.BuilderConfig{
		MinBid:             eth2p0.Gwei(conf.BuilderMinBid),
		BuilderBoostFactor: conf.BuilderBoostFactor,
		Builders:           builders,
	}
}

// builderHosts returns the hosts of the configured builders, the default data of the builder
// request auths validator clients sign for them, in the configured order.
func builderHosts(conf Config) ([]string, error) {
	hosts := make([]string, 0, len(conf.BuilderURLs))
	for _, url := range conf.BuilderURLs {
		host, err := eth2util.BuilderAuthData(url)
		if err != nil {
			return nil, err
		}

		hosts = append(hosts, string(host))
	}

	return hosts, nil
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
		builderURLGauge.WithLabelValues(withoutUserInfo(u)).Set(1)
	}

	builderMinBidGauge.WithLabelValues().Set(float64(conf.BuilderMinBid))
	builderBoostFactorGauge.WithLabelValues().Set(float64(conf.BuilderBoostFactor))
	builderMaxExecutionPaymentGauge.WithLabelValues().Set(float64(conf.BuilderMaxExecutionPayment))
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
