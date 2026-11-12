// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package proposerconfig

import (
	"bytes"
	"encoding/json"
	"io"
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

// seedFile is the seed file: the version and default_config of the proposer config file. It holds no fee recipient
// and no proposer_config: fee recipients are per validator and come from the cluster definition through the lock,
// joined with the seed's gas limit and builders when the initial config is built.
type seedFile struct {
	Version       string   `json:"version"`
	DefaultConfig Settings `json:"default_config"`
}

// ParseSeed returns the seed held by a seed file. Fields a seed cannot set, such as fee recipients, proposer_config
// or per-builder overrides, are rejected.
func ParseSeed(b []byte) (Seed, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()

	var file seedFile

	err := dec.Decode(&file)
	if err != nil {
		return Seed{}, errors.Wrap(err, "decode seed file")
	}

	err = dec.Decode(&struct{}{})
	if !errors.Is(err, io.EOF) {
		return Seed{}, errors.New("seed file has trailing data")
	}

	if major(file.Version) != major(Version) {
		return Seed{}, errors.New("unsupported seed file version", z.Str("version", file.Version), z.Str("supported", Version))
	}

	settings := file.DefaultConfig
	if settings.FeeRecipient != "" {
		return Seed{}, errors.New("seed file default_config.fee_recipient must not be set, fee recipients come from the cluster definition")
	}

	seed := Seed{BuilderBoostFactor: DefaultBuilderBoostFactor}

	seed.GasLimit, err = parseSeedUint("gas_limit", settings.GasLimit)
	if err != nil {
		return Seed{}, err
	}

	if seed.GasLimit == 0 {
		return Seed{}, errors.New("seed file default_config.gas_limit must be greater than 0")
	}

	builder := settings.Builder
	if builder == nil {
		return seed, nil
	}

	if len(builder.Builders) == 0 {
		return Seed{}, errors.New("seed file default_config.builder.builders must not be empty")
	}

	for _, entry := range builder.Builders {
		if entry != (BuilderEntry{URL: entry.URL}) {
			return Seed{}, errors.New("seed file default_config.builder.builders entry must only set url")
		}

		seed.BuilderURLs = append(seed.BuilderURLs, entry.URL)
	}

	seed.BuilderMinBid, err = parseSeedUint("builder.min_bid", builder.MinBid)
	if err != nil {
		return Seed{}, err
	}

	seed.BuilderBoostFactor, err = parseSeedUint("builder.builder_boost_factor", builder.BuilderBoostFactor)
	if err != nil {
		return Seed{}, err
	}

	if seed.BuilderBoostFactor == 0 {
		return Seed{}, errors.New("seed file default_config.builder.builder_boost_factor must be greater than 0")
	}

	seed.BuilderMaxExecutionPayment, err = parseSeedUint("builder.max_execution_payment", builder.MaxExecutionPayment)
	if err != nil {
		return Seed{}, err
	}

	return seed, nil
}

// parseSeedUint parses a seed file's decimal string value; field names it in errors.
func parseSeedUint(field, value string) (uint64, error) {
	v, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, errors.Wrap(err, "parse seed file default_config."+field)
	}

	return v, nil
}

// MarshalSeed returns the seed file holding the seed.
func MarshalSeed(seed Seed) ([]byte, error) {
	b, err := json.MarshalIndent(seedFile{
		Version:       Version,
		DefaultConfig: Settings{GasLimit: strconv.FormatUint(seed.GasLimit, 10), Builder: seed.Builder()},
	}, "", "  ")
	if err != nil {
		return nil, errors.Wrap(err, "marshal seed file")
	}

	return b, nil
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

	boostFactorSet := s.BuilderBoostFactor != DefaultBuilderBoostFactor || slices.Contains(s.NonDefault, "proposer-config-builder-boost-factor")
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
