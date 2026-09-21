// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util/registration"
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
// if it doesn't already exist, mirroring what charon registers with builders: the
// effective builder registrations including operator overrides, falling back to the
// cluster lock. An existing file is never modified.
func writeProposerConfigFile(conf Config, lock *cluster.Lock, nodeIdx cluster.NodeIdx,
	feeRecipientFunc func(core.PubKey) string, gasLimitFunc func(core.PubKey) uint64,
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
		gasLimit     uint64
	}

	var (
		all       []valSettings
		feeCounts = make(map[string]int)
		gasCounts = make(map[uint64]int)
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

		gasLimit := gasLimitFunc(corePubkey)
		if gasLimit == 0 {
			gasLimit = registration.DefaultGasLimit
		}

		vs := valSettings{
			pubshareHex:  fmt.Sprintf("%#x", pubshare),
			feeRecipient: feeRecipient,
			gasLimit:     gasLimit,
		}

		all = append(all, vs)
		feeCounts[vs.feeRecipient]++
		gasCounts[vs.gasLimit]++
	}

	// The default config holds the per-field majority values, ties broken by the
	// first validator holding them, so the common uniform cluster emits no entries.
	var (
		defaultFee string
		defaultGas uint64
	)

	for _, vs := range all {
		if feeCounts[vs.feeRecipient] > feeCounts[defaultFee] {
			defaultFee = vs.feeRecipient
		}

		if gasCounts[vs.gasLimit] > gasCounts[defaultGas] {
			defaultGas = vs.gasLimit
		}
	}

	config := proposerConfigJSON{
		Version:        proposerConfigVersion,
		ProposerConfig: make(map[string]proposerSettingsJSON),
		DefaultConfig: proposerSettingsJSON{
			FeeRecipient: defaultFee,
			GasLimit:     strconv.FormatUint(defaultGas, 10),
		},
	}

	if builderConfigured(conf) {
		builderEntries := make([]builderEntryJSON, 0, len(conf.BuilderURLs))
		for _, u := range conf.BuilderURLs {
			builderEntries = append(builderEntries, builderEntryJSON{URL: u})
		}

		config.DefaultConfig.Builder = &builderSettingsJSON{
			MinBid:              strconv.FormatUint(conf.BuilderMinBid, 10),
			BuilderBoostFactor:  strconv.FormatUint(conf.BuilderBoostFactor, 10),
			MaxExecutionPayment: strconv.FormatUint(conf.BuilderMaxExecutionPayment, 10),
			Builders:            builderEntries,
		}
	}

	// Entries only carry the fields diverging from the default config.
	for _, vs := range all {
		var entry proposerSettingsJSON

		if vs.feeRecipient != defaultFee {
			entry.FeeRecipient = vs.feeRecipient
		}

		if vs.gasLimit != defaultGas {
			entry.GasLimit = strconv.FormatUint(vs.gasLimit, 10)
		}

		if entry == (proposerSettingsJSON{}) {
			continue // Covered by the default config.
		}

		config.ProposerConfig[vs.pubshareHex] = entry
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

// wireProposerConfigFile generates the proposer config file, logging failures instead
// of returning them so generation never prevents duties.
func wireProposerConfigFile(ctx context.Context, conf Config, lock *cluster.Lock, nodeIdx cluster.NodeIdx,
	feeRecipientFunc func(core.PubKey) string, gasLimitFunc func(core.PubKey) uint64,
) {
	created, err := writeProposerConfigFile(conf, lock, nodeIdx, feeRecipientFunc, gasLimitFunc)
	if err != nil {
		log.Error(ctx, "Failed generating proposer config file, VC proposer settings must be configured manually", err)
		return
	}

	if created {
		log.Info(ctx, "Generated proposer config file for validator clients",
			z.Str("path", filepath.Join(filepath.Dir(conf.LockFile), proposerConfigDir, proposerConfigFilename)))
	}
}
