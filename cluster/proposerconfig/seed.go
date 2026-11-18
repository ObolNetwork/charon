// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package proposerconfig

import (
	"net/url"
	"slices"
	"strconv"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
)

// Seed holds the flags seeding the initial (revision 0) proposer config.
type Seed struct {
	GasLimit                   uint64
	BuilderURLs                []string
	BuilderMinBid              uint64
	BuilderBoostFactor         uint64
	BuilderMaxExecutionPayment uint64
	// NonDefault names the seed flags set explicitly rather than left at their defaults.
	NonDefault []string
}

// Validate checks the seed flags.
func (s Seed) Validate() error {
	err := validateBuilderURLs("proposer-config-builder-urls", s.BuilderURLs)
	if err != nil {
		return err
	}

	if s.GasLimit == 0 {
		return errors.New("proposer-config-gas-limit must be greater than 0")
	}

	if s.BuilderBoostFactor == 0 {
		return errors.New("proposer-config-builder-boost-factor must be greater than 0")
	}

	boostFactorSet := slices.Contains(s.NonDefault, "proposer-config-builder-boost-factor")
	if len(s.BuilderURLs) == 0 && (s.BuilderMinBid != 0 || boostFactorSet || s.BuilderMaxExecutionPayment != 0) {
		return errors.New("proposer-config-builder-min-bid, proposer-config-builder-boost-factor and " +
			"proposer-config-builder-max-execution-payment require proposer-config-builder-urls")
	}

	return nil
}

// validateBuilderURLs checks each builder URL is a unique http(s) URL with a host that fits a proposal;
// flag names the URLs' flag in errors.
func validateBuilderURLs(flag string, urls []string) error {
	seen := make(map[string]bool)

	for i, u := range urls {
		parsed, err := url.Parse(u)
		if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" {
			// The URL is left out: one that doesn't parse cannot be redacted.
			return errors.New(flag+" entry is not a valid http(s) URL", z.Int("index", i))
		}

		if seen[u] {
			return errors.New(flag+" entry is duplicated", z.Str("url", log.RedactURL(u, true)))
		}

		seen[u] = true

		// A builder's URL is agreed with the proposals of its bids, which can't carry a longer one.
		if len(u) > core.MaxBuilderURLSize {
			return errors.New(flag+" entry is longer than the maximum", z.Int("max", core.MaxBuilderURLSize))
		}
	}

	return nil
}

// FlagValues returns the settings' gas limit and builder values keyed by the seeding flag setting them: the
// builder URLs as a list, the other values as one element, the builder flags absent without a builder.
func FlagValues(s Settings) map[string][]string {
	vals := map[string][]string{"proposer-config-gas-limit": {s.GasLimit}}
	if s.Builder == nil {
		return vals
	}

	b := flattenBuilder(s.Builder)
	vals["proposer-config-builder-urls"] = b.urls
	vals["proposer-config-builder-min-bid"] = []string{b.minBid}
	vals["proposer-config-builder-boost-factor"] = []string{b.boostFactor}
	vals["proposer-config-builder-max-execution-payment"] = []string{b.maxExecutionPayment}

	return vals
}

// Builder returns the builder settings, or nil if no builder URLs are configured.
func (s Seed) Builder() *Builder {
	if len(s.BuilderURLs) == 0 {
		return nil
	}

	entries := make([]BuilderEntry, 0, len(s.BuilderURLs))
	for _, u := range s.BuilderURLs {
		entries = append(entries, BuilderEntry{URL: u})
	}

	return &Builder{
		MinBid:              strconv.FormatUint(s.BuilderMinBid, 10),
		BuilderBoostFactor:  strconv.FormatUint(s.BuilderBoostFactor, 10),
		MaxExecutionPayment: strconv.FormatUint(s.BuilderMaxExecutionPayment, 10),
		Builders:            entries,
	}
}
