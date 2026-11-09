// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package proposerconfig

import (
	"net/url"
	"slices"
	"strconv"

	"github.com/obolnetwork/charon/app/errors"
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

	for _, u := range urls {
		if seen[u] {
			return errors.New(flag+" entry is duplicated", z.Str("url", u))
		}

		seen[u] = true

		parsed, err := url.Parse(u)
		if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" {
			return errors.New(flag+" entry is not a valid http(s) URL", z.Str("url", u))
		}

		// A builder's URL is agreed with the proposals of its bids, which can't carry a longer one.
		if len(u) > core.MaxBuilderURLSize {
			return errors.New(flag+" entry is longer than the maximum", z.Int("max", core.MaxBuilderURLSize))
		}
	}

	return nil
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
