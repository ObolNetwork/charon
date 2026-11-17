// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package vcbundle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
)

type tekuBuilder struct {
	Enabled            bool                          `json:"enabled"`
	GasLimit           string                        `json:"gas_limit"`
	MinBid             string                        `json:"min_bid,omitempty"`
	BuilderBoostFactor string                        `json:"builder_boost_factor,omitempty"`
	Builders           []proposerconfig.BuilderEntry `json:"builders,omitempty"`
}

type tekuSettings struct {
	FeeRecipient string      `json:"fee_recipient"`
	Builder      tekuBuilder `json:"builder"`
}

type tekuConfig struct {
	ProposerConfig map[string]tekuSettings `json:"proposer_config"`
	DefaultConfig  tekuSettings            `json:"default_config"`
}

// proposerConfigFiles returns the client's proposer settings files.
func proposerConfigFiles(client Client, cfg proposerconfig.Config, keystores []keystoreFile) ([]bundleFile, error) {
	single := func(path string, render func(proposerconfig.Config) ([]byte, error)) ([]bundleFile, error) {
		b, err := render(cfg)
		if err != nil {
			return nil, err
		}

		return []bundleFile{{Path: path, Data: b, Mode: publicMode}}, nil
	}

	switch client {
	case Teku:
		return single(tekuSettingsPath, renderTeku)
	case Prysm:
		return single(prysmSettingsPath, renderPrysm)
	case Lodestar:
		return single(lodestarSettingsPath, renderLodestar)
	case Nimbus:
		var files []bundleFile

		for _, k := range keystores {
			files = append(files,
				bundleFile{Path: filepath.Join("validators", k.Pubkey, "suggested_fee_recipient.hex"), Data: []byte(cfg.FeeRecipient(k.Pubkey) + "\n"), Mode: publicMode},
				bundleFile{Path: filepath.Join("validators", k.Pubkey, "suggested_gas_limit.json"), Data: []byte(cfg.DefaultConfig.GasLimit + "\n"), Mode: publicMode},
			)
		}

		return files, nil
	case Lighthouse:
		return lighthouseFiles(cfg, keystores)
	default:
		return nil, errors.New("unknown validator client", z.Str("client", string(client)))
	}
}

// lighthouseFiles returns Lighthouse's validator and builder definitions. The definitions point at the keystores
// by absolute path, since the files are moved into Lighthouse's validators directory.
func lighthouseFiles(cfg proposerconfig.Config, keystores []keystoreFile) ([]bundleFile, error) {
	absolute := make([]keystoreFile, 0, len(keystores))

	for _, k := range keystores {
		var err error

		k.KeystorePath, err = filepath.Abs(k.KeystorePath)
		if err != nil {
			return nil, errors.Wrap(err, "absolute keystore path")
		}

		k.PasswordPath, err = filepath.Abs(k.PasswordPath)
		if err != nil {
			return nil, errors.Wrap(err, "absolute keystore password path")
		}

		absolute = append(absolute, k)
	}

	definitions, err := renderLighthouseDefinitions(cfg, absolute)
	if err != nil {
		return nil, err
	}

	builders, err := renderLighthouseBuilders(cfg.DefaultConfig.Builder)
	if err != nil {
		return nil, err
	}

	return []bundleFile{
		{Path: filepath.Join("validators", "validator_definitions.yml"), Data: definitions, Mode: publicMode},
		{Path: lighthouseBuildersPath, Data: builders, Mode: publicMode},
	}, nil
}

// renderTeku returns Teku's proposer config file.
func renderTeku(cfg proposerconfig.Config) ([]byte, error) {
	enabled := cfg.DefaultConfig.Builder != nil
	settings := func(feeRecipient, gasLimit string) tekuSettings {
		return tekuSettings{FeeRecipient: feeRecipient, Builder: tekuBuilder{Enabled: enabled, GasLimit: gasLimit}}
	}

	out := tekuConfig{
		ProposerConfig: make(map[string]tekuSettings),
		DefaultConfig:  settings(cfg.DefaultConfig.FeeRecipient, cfg.DefaultConfig.GasLimit),
	}

	for pubkey := range cfg.ProposerConfig {
		out.ProposerConfig[pubkey] = settings(cfg.FeeRecipient(pubkey), cfg.DefaultConfig.GasLimit)
	}

	// Teku falls back to the default config per field, so the builders are only in it. It takes the max execution
	// payment per builder only.
	b := cfg.DefaultConfig.Builder
	if b != nil {
		out.DefaultConfig.Builder.MinBid = b.MinBid
		out.DefaultConfig.Builder.BuilderBoostFactor = b.BuilderBoostFactor

		for _, entry := range b.Builders {
			entry.MaxExecutionPayment = orDefault(entry.MaxExecutionPayment, b.MaxExecutionPayment)
			out.DefaultConfig.Builder.Builders = append(out.DefaultConfig.Builder.Builders, entry)
		}
	}

	return marshalJSON(out)
}

type prysmBuilder struct {
	MinBid              string                        `json:"min_bid,omitempty"`
	BuilderBoostFactor  string                        `json:"builder_boost_factor,omitempty"`
	MaxExecutionPayment string                        `json:"max_execution_payment,omitempty"`
	Builders            []proposerconfig.BuilderEntry `json:"builders,omitempty"`
}

type prysmSettings struct {
	FeeRecipient string        `json:"fee_recipient"`
	GasLimit     string        `json:"gas_limit"`
	Builder      *prysmBuilder `json:"builder,omitempty"`
}

type prysmConfig struct {
	Version        int                      `json:"version"`
	ProposerConfig map[string]prysmSettings `json:"proposer_config"`
	DefaultConfig  prysmSettings            `json:"default_config"`
}

// renderPrysm returns Prysm's version 2 proposer settings file: the gas limit is set at the top level and the default
// builder block carries the builder settings. The legacy builder fields (enabled, gas limit) are left out, Prysm drops
// them from the gloas fork.
func renderPrysm(cfg proposerconfig.Config) ([]byte, error) {
	out := prysmConfig{
		Version:        2,
		ProposerConfig: make(map[string]prysmSettings),
		DefaultConfig:  prysmSettings{FeeRecipient: cfg.DefaultConfig.FeeRecipient, GasLimit: cfg.DefaultConfig.GasLimit},
	}

	for pubkey := range cfg.ProposerConfig {
		out.ProposerConfig[pubkey] = prysmSettings{FeeRecipient: cfg.FeeRecipient(pubkey), GasLimit: cfg.DefaultConfig.GasLimit}
	}

	b := cfg.DefaultConfig.Builder
	if b != nil {
		out.DefaultConfig.Builder = &prysmBuilder{
			MinBid:              b.MinBid,
			BuilderBoostFactor:  b.BuilderBoostFactor,
			MaxExecutionPayment: b.MaxExecutionPayment,
			Builders:            b.Builders,
		}
	}

	return marshalJSON(out)
}

type lodestarBuilder struct {
	GasLimit            string                        `json:"gas_limit"`
	MinBid              string                        `json:"min_bid,omitempty"`
	BoostFactor         string                        `json:"boost_factor,omitempty"`
	MaxExecutionPayment string                        `json:"max_execution_payment,omitempty"`
	Builders            []proposerconfig.BuilderEntry `json:"builders,omitempty"`
}

type lodestarSettings struct {
	FeeRecipient string          `json:"fee_recipient"`
	Builder      lodestarBuilder `json:"builder"`
}

type lodestarConfig struct {
	ProposerConfig map[string]lodestarSettings `json:"proposer_config"`
	DefaultConfig  lodestarSettings            `json:"default_config"`
}

// renderLodestar returns Lodestar's proposer settings file. It is JSON, which Lodestar reads as YAML.
func renderLodestar(cfg proposerconfig.Config) ([]byte, error) {
	out := lodestarConfig{
		ProposerConfig: make(map[string]lodestarSettings),
		DefaultConfig: lodestarSettings{
			FeeRecipient: cfg.DefaultConfig.FeeRecipient,
			Builder:      lodestarBuilder{GasLimit: cfg.DefaultConfig.GasLimit},
		},
	}

	for pubkey := range cfg.ProposerConfig {
		out.ProposerConfig[pubkey] = lodestarSettings{
			FeeRecipient: cfg.FeeRecipient(pubkey),
			Builder:      lodestarBuilder{GasLimit: cfg.DefaultConfig.GasLimit},
		}
	}

	b := cfg.DefaultConfig.Builder
	if b != nil {
		out.DefaultConfig.Builder.MinBid = b.MinBid
		out.DefaultConfig.Builder.BoostFactor = b.BuilderBoostFactor
		out.DefaultConfig.Builder.MaxExecutionPayment = b.MaxExecutionPayment
		out.DefaultConfig.Builder.Builders = b.Builders
	}

	return marshalJSON(out)
}

// renderLighthouseDefinitions returns Lighthouse's validator_definitions.yml for the keystores, which it reads
// at the paths given.
func renderLighthouseDefinitions(cfg proposerconfig.Config, keystores []keystoreFile) ([]byte, error) {
	var buf bytes.Buffer

	gas, err := parseNumber("gas limit", cfg.DefaultConfig.GasLimit)
	if err != nil {
		return nil, err
	}

	for _, k := range keystores {
		buf.WriteString("- enabled: true\n")
		_, _ = fmt.Fprintf(&buf, "  voting_public_key: %q\n", k.Pubkey)
		buf.WriteString("  type: local_keystore\n")
		_, _ = fmt.Fprintf(&buf, "  voting_keystore_path: %s\n", strconv.Quote(k.KeystorePath))
		_, _ = fmt.Fprintf(&buf, "  voting_keystore_password_path: %s\n", strconv.Quote(k.PasswordPath))
		_, _ = fmt.Fprintf(&buf, "  suggested_fee_recipient: %q\n", cfg.FeeRecipient(k.Pubkey))
		_, _ = fmt.Fprintf(&buf, "  gas_limit: %d\n", gas)
		_, _ = fmt.Fprintf(&buf, "  builder_proposals: %t\n", cfg.DefaultConfig.Builder != nil)
	}

	return buf.Bytes(), nil
}

type lighthouseBuilderEntry struct {
	Enabled             bool    `json:"enabled"`
	URL                 string  `json:"url"`
	MaxExecutionPayment uint64  `json:"max_execution_payment"`
	MinBid              *uint64 `json:"min_bid,omitempty"`
	BuilderBoostFactor  *uint64 `json:"builder_boost_factor,omitempty"`
}

type lighthouseBuilders struct {
	MinBid             uint64                   `json:"min_bid"`
	BuilderBoostFactor uint64                   `json:"builder_boost_factor"`
	Builders           []lighthouseBuilderEntry `json:"builders"`
}

// renderLighthouseBuilders returns Lighthouse's builder_definitions.yml, as JSON which Lighthouse reads as YAML.
// An entry's max execution payment falls back to the block's; its min bid and boost factor are only set when the
// entry sets them. Without a builder block it lists no builders, so it replaces the file of an earlier bundle.
func renderLighthouseBuilders(builder *proposerconfig.Builder) ([]byte, error) {
	if builder == nil {
		return marshalJSON(lighthouseBuilders{BuilderBoostFactor: proposerconfig.DefaultBuilderBoostFactor, Builders: []lighthouseBuilderEntry{}})
	}

	minBid, err := parseNumber("min_bid", builder.MinBid)
	if err != nil {
		return nil, err
	}

	boostFactor, err := parseNumber("builder_boost_factor", builder.BuilderBoostFactor)
	if err != nil {
		return nil, err
	}

	out := lighthouseBuilders{MinBid: minBid, BuilderBoostFactor: boostFactor}

	for _, b := range builder.Builders {
		maxPayment := b.MaxExecutionPayment
		if maxPayment == "" {
			maxPayment = builder.MaxExecutionPayment
		}

		entry := lighthouseBuilderEntry{Enabled: true, URL: b.URL}

		entry.MaxExecutionPayment, err = parseNumber("max_execution_payment", maxPayment)
		if err != nil {
			return nil, err
		}

		entry.MinBid, err = parseOptionalNumber("min_bid", b.MinBid)
		if err != nil {
			return nil, err
		}

		entry.BuilderBoostFactor, err = parseOptionalNumber("builder_boost_factor", b.BuilderBoostFactor)
		if err != nil {
			return nil, err
		}

		out.Builders = append(out.Builders, entry)
	}

	return marshalJSON(out)
}

// parseNumber parses a decimal proposer config value.
func parseNumber(name, value string) (uint64, error) {
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, errors.Wrap(err, "parse "+name, z.Str("value", value))
	}

	return n, nil
}

// parseOptionalNumber parses a decimal proposer config value, nil when empty.
func parseOptionalNumber(name, value string) (*uint64, error) {
	if value == "" {
		return nil, nil //nolint:nilnil // absent value
	}

	n, err := parseNumber(name, value)
	if err != nil {
		return nil, err
	}

	return &n, nil
}

// marshalJSON returns v as indented JSON with a trailing newline.
func marshalJSON(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, errors.Wrap(err, "marshal json")
	}

	return append(b, '\n'), nil
}
