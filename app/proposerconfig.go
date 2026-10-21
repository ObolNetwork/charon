// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
)

// proposerConfigDir and proposerConfigFilename locate the generated validator client
// proposer configuration file in a dedicated directory next to the cluster lock file,
// keeping validator client facing configuration separate from charon's own files.
const (
	proposerConfigDir      = "vc-config"
	proposerConfigFilename = "proposer-config.json"

	// proposerConfigVersion is the charon proposer configuration schema version,
	// bumped on backwards incompatible schema changes.
	proposerConfigVersion = 1
)

// proposerConfigJSON is charon's canonical proposer configuration schema, closely
// modelled on the Prysm/Teku proposer settings format minus its pre-gloas legacy
// fields. It is consumed by per validator client adapters (the CDVN wrapper scripts)
// which render each client's native format from it.
//
// The consumer contract: a validator absent from proposer_config uses default_config;
// entries are only emitted for validators diverging from it and only carry the
// diverging fields. Any absent field falls back to the corresponding field one level
// up, ultimately default_config. Since jq's // operator swallows false, the schema
// must never make a boolean field optional.
type proposerConfigJSON struct {
	// Version is the charon proposer configuration schema version.
	Version uint32 `json:"version"`
	// ProposerConfig maps this node's validator public shares (the identities the
	// validator client manages) to their proposer settings. Only validators whose
	// settings diverge from default_config have an entry.
	ProposerConfig map[string]proposerSettingsJSON `json:"proposer_config"`
	// DefaultConfig applies to validators without an explicit entry, holding the
	// majority settings across this node's validators.
	DefaultConfig proposerSettingsJSON `json:"default_config"`
}

// proposerSettingsJSON holds one validator's proposer settings. All fields are set
// on default_config; a proposer_config entry only carries the fields diverging from
// it, the rest fall back to default_config.
type proposerSettingsJSON struct {
	FeeRecipient string `json:"fee_recipient,omitempty"`
	// GasLimit is the preferred target gas limit for the execution payload.
	GasLimit string `json:"gas_limit,omitempty"`
	// Builder holds the gloas builder configuration, only emitted on default_config
	// and only when builder URLs are configured. Per-validator overrides may be
	// emitted additively in the future.
	Builder *builderSettingsJSON `json:"builder,omitempty"`
}

// builderSettingsJSON holds the builder configuration defaults; each entry in
// Builders may override them (mirroring how proposer_config entries override
// default_config), falling back to these values for absent fields.
type builderSettingsJSON struct {
	// MinBid is the minimum bid value in gwei, applying to p2p gossip bids as well.
	MinBid string `json:"min_bid"`
	// BuilderBoostFactor is the percentage multiplier applied to builder bid values.
	BuilderBoostFactor string `json:"builder_boost_factor"`
	// MaxExecutionPayment is the maximum execution layer payment in gwei counted
	// when valuing a builder bid.
	MaxExecutionPayment string `json:"max_execution_payment"`
	// Builders lists the builders to request execution payload bids from directly.
	Builders []builderEntryJSON `json:"builders"`
}

// builderEntryJSON is one builder to request bids from directly. The override
// fields are part of the schema for consumers but charon does not emit them yet,
// all builders currently share the enclosing defaults.
type builderEntryJSON struct {
	URL string `json:"url"`
	// The fields below optionally override the enclosing builderSettingsJSON values
	// for this builder; if missing, use the enclosing value.
	MinBid              string `json:"min_bid,omitempty"`
	BuilderBoostFactor  string `json:"builder_boost_factor,omitempty"`
	MaxExecutionPayment string `json:"max_execution_payment,omitempty"`
}

// writeProposerConfigFile generates the validator client proposer configuration file
// if it doesn't already exist. Fee recipients mirror what charon registers with builders:
// the effective builder registrations including operator overrides, falling back to the
// cluster lock. The gas limit is the configured proposer gas limit. An existing file is
// never modified.
func writeProposerConfigFile(conf Config, lock *cluster.Lock, nodeIdx cluster.NodeIdx,
	feeRecipientFunc func(core.PubKey) string,
) (bool, error) {
	dir := filepath.Join(filepath.Dir(conf.LockFile), proposerConfigDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, errors.Wrap(err, "create proposer config directory", z.Str("dir", dir))
	}

	path := filepath.Join(dir, proposerConfigFilename)

	if info, err := os.Stat(path); err == nil {
		if info.IsDir() {
			return false, errors.New("proposer config file path is a directory", z.Str("path", path))
		}

		return false, nil // Never modify an existing file.
	} else if !os.IsNotExist(err) {
		return false, errors.Wrap(err, "stat proposer config file", z.Str("path", path))
	}

	feeRecipients := lock.FeeRecipientAddresses()

	// Resolve each validator's settings, counting identical ones to determine the
	// majority default below.
	type valSettings struct {
		pubshareHex  string
		feeRecipient string
	}

	var (
		all       []valSettings
		feeCounts = make(map[string]int)
	)

	for vi, val := range lock.Validators {
		pubshare, err := val.PublicShare(nodeIdx.PeerIdx)
		if err != nil {
			return false, errors.Wrap(err, "public share", z.Int("validator", vi))
		}

		corePubkey, err := core.PubKeyFromBytes(val.PubKey)
		if err != nil {
			return false, errors.Wrap(err, "core pubkey", z.Int("validator", vi))
		}

		feeRecipient := feeRecipientFunc(corePubkey)
		if feeRecipient == "" {
			feeRecipient = feeRecipients[vi]
		}

		vs := valSettings{
			pubshareHex:  fmt.Sprintf("%#x", pubshare),
			feeRecipient: feeRecipient,
		}

		all = append(all, vs)
		feeCounts[vs.feeRecipient]++
	}

	// The default config holds the majority fee recipient, ties broken by the first
	// validator holding it, so the common uniform cluster emits no entries.
	var defaultFee string

	for _, vs := range all {
		if feeCounts[vs.feeRecipient] > feeCounts[defaultFee] {
			defaultFee = vs.feeRecipient
		}
	}

	config := proposerConfigJSON{
		Version:        proposerConfigVersion,
		ProposerConfig: make(map[string]proposerSettingsJSON),
		DefaultConfig: proposerSettingsJSON{
			FeeRecipient: defaultFee,
			GasLimit:     strconv.FormatUint(conf.ProposerGasLimit, 10),
			Builder:      builderSettings(conf),
		},
	}

	// Entries only carry the fields diverging from the default config.
	for _, vs := range all {
		if vs.feeRecipient == defaultFee {
			continue // Covered by the default config.
		}

		config.ProposerConfig[vs.pubshareHex] = proposerSettingsJSON{FeeRecipient: vs.feeRecipient}
	}

	b, err := json.Marshal(config)
	if err != nil {
		return false, errors.Wrap(err, "marshal proposer config")
	}

	//nolint:gosec // Configuration file without secrets, needs to be readable by validator clients.
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		return false, errors.Wrap(err, "write proposer config file", z.Str("path", path))
	}

	return true, nil
}

// builderSettings returns the builder settings of the proposer config, nil if no builder
// URLs are configured.
func builderSettings(conf Config) *builderSettingsJSON {
	if !builderConfigured(conf) {
		return nil
	}

	builderEntries := make([]builderEntryJSON, 0, len(conf.BuilderURLs))
	for _, u := range conf.BuilderURLs {
		builderEntries = append(builderEntries, builderEntryJSON{URL: u})
	}

	return &builderSettingsJSON{
		MinBid:              strconv.FormatUint(conf.BuilderMinBid, 10),
		BuilderBoostFactor:  strconv.FormatUint(conf.BuilderBoostFactor, 10),
		MaxExecutionPayment: strconv.FormatUint(conf.BuilderMaxExecutionPayment, 10),
		Builders:            builderEntries,
	}
}

// proposerConfigMatches returns whether the builder settings and the gas limits of the
// existing proposer config file match the configured builder and proposer gas limit flags.
func proposerConfigMatches(conf Config, path string) (builderMatches bool, gasMatches bool, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return false, false, errors.Wrap(err, "read proposer config file", z.Str("path", path))
	}

	var config proposerConfigJSON
	if err := json.Unmarshal(b, &config); err != nil {
		return false, false, errors.Wrap(err, "decode proposer config file", z.Str("path", path))
	}

	gasLimit := strconv.FormatUint(conf.ProposerGasLimit, 10)

	gasMatches = config.DefaultConfig.GasLimit == gasLimit
	for _, entry := range config.ProposerConfig {
		if entry.GasLimit != "" && entry.GasLimit != gasLimit {
			gasMatches = false
		}
	}

	return builderSettingsEqual(config.DefaultConfig.Builder, builderSettings(conf)), gasMatches, nil
}

// builderSettingsEqual returns whether both builder settings are absent, or equal.
func builderSettingsEqual(a, b *builderSettingsJSON) bool {
	if a == nil || b == nil {
		return a == b
	}

	return a.MinBid == b.MinBid &&
		a.BuilderBoostFactor == b.BuilderBoostFactor &&
		a.MaxExecutionPayment == b.MaxExecutionPayment &&
		slices.Equal(a.Builders, b.Builders)
}

// wireProposerConfigFile generates the proposer config file, or warns if the builder settings or
// gas limits of an existing one differ from the flags, logging failures instead of returning them
// so generation never prevents duties.
func wireProposerConfigFile(ctx context.Context, conf Config, lock *cluster.Lock, nodeIdx cluster.NodeIdx,
	feeRecipientFunc func(core.PubKey) string,
) {
	if conf.TestConfig.Lock != nil {
		// In-memory test lock, there is no cluster directory to write the file into.
		return
	}

	created, err := writeProposerConfigFile(conf, lock, nodeIdx, feeRecipientFunc)
	if err != nil {
		log.Error(ctx, "Failed generating proposer config file, VC proposer settings must be configured manually", err)
		return
	}

	path := filepath.Join(filepath.Dir(conf.LockFile), proposerConfigDir, proposerConfigFilename)

	if created {
		log.Info(ctx, "Generated proposer config file for validator clients", z.Str("path", path))
		return
	}

	// The flags only seed a new file, the cluster changes builders and gas limits together.
	builderMatches, gasMatches, err := proposerConfigMatches(conf, path)
	if err != nil {
		log.Warn(ctx, "Failed checking the proposer config file against the flags", err)
		return
	}

	if !builderMatches {
		log.Warn(ctx, "Builder flags differ from the proposer config file and only apply to a new file, "+
			"change its builders with `charon proposerconfig edit` in sync with the other peers", nil, z.Str("path", path))
	}

	if !gasMatches {
		log.Warn(ctx, "Proposer gas limit flag differs from the proposer config file and only applies to a new file, "+
			"change its gas limits in sync with the other peers", nil, z.Str("path", path), z.U64("proposer_gas_limit", conf.ProposerGasLimit))
	}
}
