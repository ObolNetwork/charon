// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"crypto/sha256"
	"fmt"
	"slices"
)

// builderConfigHash returns a digest of the canonicalised builder configuration.
// It is exchanged via the peerinfo protocol so peers can detect divergent builder
// configurations, which would produce divergent (non-aggregatable) builder duties.
func builderConfigHash(conf Config) []byte {
	urls := slices.Clone(conf.ProposerConfigSeed.BuilderURLs)
	slices.Sort(urls)

	h := sha256.New()
	_, _ = h.Write([]byte("charon/builder_config/v1\n"))

	for _, u := range urls {
		_, _ = fmt.Fprintf(h, "url:%s\n", u)
	}

	_, _ = fmt.Fprintf(h, "min_bid:%d\nbuilder_boost_factor:%d\nmax_execution_payment:%d\n",
		conf.ProposerConfigSeed.BuilderMinBid, conf.ProposerConfigSeed.BuilderBoostFactor, conf.ProposerConfigSeed.BuilderMaxExecutionPayment)

	return h.Sum(nil)
}
