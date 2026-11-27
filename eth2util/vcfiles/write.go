// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package vcfiles

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
	"github.com/obolnetwork/charon/eth2util"
)

const (
	// FlagsFile is the name of the file holding the client's flags derived from the proposer config.
	FlagsFile = "vc-flags.txt"

	secretMode = 0o600
	publicMode = 0o644
)

// Config configures the files written for a validator client.
type Config struct {
	Client             Client
	OutputDir          string
	ProposerConfigFile string
	ValidatorKeysDir   string
	// LighthouseDir is Lighthouse's data directory as Lighthouse sees it, absolute. Its validator definitions name
	// the keystores under it.
	LighthouseDir string
	// BuilderAPI is charon run's builder API flag: before the gloas fork the proposer config holds no builders and
	// it alone enables builder proposals on the client.
	BuilderAPI bool
}

// outFile is a file to write, its path relative to the output directory.
type outFile struct {
	Path string
	Data []byte
	Mode os.FileMode
}

// WriteKeys writes the node's key shares in the client's layout and returns the paths of the files written,
// relative to the output directory, sorted. Everything is rendered before anything is written.
func WriteKeys(ctx context.Context, conf Config) ([]string, error) {
	err := checkClient(ctx, conf.Client)
	if err != nil {
		return nil, err
	}

	keystores, err := listKeystores(conf.ValidatorKeysDir)
	if err != nil {
		return nil, err
	}

	files, err := keystoreFiles(ctx, conf.Client, conf.ValidatorKeysDir, keystores)
	if err != nil {
		return nil, err
	}

	return writeFiles(conf.OutputDir, files)
}

// WriteConfig writes the client's proposer settings and flags from the proposer config file and returns the paths
// of the files written, relative to the output directory, sorted. Everything is rendered before anything is written.
func WriteConfig(ctx context.Context, conf Config) ([]string, error) {
	err := checkClient(ctx, conf.Client)
	if err != nil {
		return nil, err
	}

	if conf.Client == Lighthouse && !path.IsAbs(conf.LighthouseDir) {
		return nil, errors.New("lighthouse's validator definitions need its absolute data directory, as lighthouse sees it",
			z.Str("lighthouse_dir", conf.LighthouseDir))
	}

	// These clients take settings per validator, named by the key shares' public keys.
	var keystores []keystoreFile
	if conf.Client == Prysm || conf.Client == Nimbus || conf.Client == Lighthouse {
		keystores, err = listKeystores(conf.ValidatorKeysDir)
		if err != nil {
			return nil, err
		}
	}

	cfg, err := loadProposerConfig(conf.ProposerConfigFile)
	if err != nil {
		return nil, err
	}

	logBuilders(ctx, conf.Client, cfg.DefaultConfig.Builder)

	builderEnabled := conf.BuilderAPI || cfg.DefaultConfig.Builder != nil

	files, err := proposerConfigFiles(conf.Client, cfg, keystores, conf.LighthouseDir, builderEnabled)
	if err != nil {
		return nil, err
	}

	files = append(files, outFile{Path: FlagsFile, Data: renderFlags(vcFlags(conf.Client, cfg, builderEnabled)), Mode: publicMode})

	return writeFiles(conf.OutputDir, files)
}

// checkClient returns an error for an unknown client and logs the client version the files are made for.
func checkClient(ctx context.Context, client Client) error {
	if !slices.Contains(clients, client) {
		return errors.New("unknown validator client, use one of: "+join(clients), z.Str("client", string(client)))
	}

	log.Info(ctx, "Validator client files made for client version", z.Str("client", string(client)), z.Str("version", clientVersions[client]))

	return nil
}

// writeFiles writes the files under outputDir and returns their paths, sorted.
func writeFiles(outputDir string, files []outFile) ([]string, error) {
	var resp []string

	for _, f := range files {
		err := writeFile(outputDir, f.Path, f.Data, f.Mode)
		if err != nil {
			return nil, err
		}

		resp = append(resp, f.Path)
	}

	slices.Sort(resp)

	return resp, nil
}

var lighthouseBuildersPath = filepath.Join("validators", "builder_definitions.yml")

const (
	tekuSettingsPath     = "teku-proposer-config.json"
	prysmSettingsPath    = "prysm-proposer-settings.json"
	lodestarSettingsPath = "lodestar-proposer-settings.yml"
)

// loadProposerConfig returns the config of the proposer config file as charon run writes it, keyed by this node's
// public shares, which are the keystores' public keys. The file is checked as far as it can be without the cluster
// lock, which its revision hash and signatures need.
func loadProposerConfig(path string) (proposerconfig.Config, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return proposerconfig.Config{}, errors.New("proposer config file not found, charon run writes it on start", z.Str("path", path))
	} else if err != nil {
		return proposerconfig.Config{}, errors.Wrap(err, "read proposer config file", z.Str("path", path))
	}

	doc, err := proposerconfig.Unmarshal(b)
	if err != nil {
		return proposerconfig.Config{}, errors.Wrap(err, "parse proposer config file", z.Str("path", path))
	}

	if !proposerconfig.SupportedVersion(doc.Version) {
		return proposerconfig.Config{}, errors.New("unsupported proposer config file version", z.Str("version", doc.Version), z.Str("supported", proposerconfig.Version), z.Str("path", path))
	}

	// Charon writes lowercase keys but accepts others, as the keystores' public keys are matched lowercase.
	cfg := doc.Config
	cfg.ProposerConfig = make(map[string]proposerconfig.Settings, len(doc.Config.ProposerConfig))

	for key, settings := range doc.Config.ProposerConfig {
		lower := strings.ToLower(key)

		_, ok := cfg.ProposerConfig[lower]
		if ok {
			return proposerconfig.Config{}, errors.New("duplicate proposer config key", z.Str("key", lower), z.Str("path", path))
		}

		cfg.ProposerConfig[lower] = settings
	}

	err = validateProposerConfig(cfg)
	if err != nil {
		return proposerconfig.Config{}, errors.Wrap(err, "invalid proposer config file", z.Str("path", path))
	}

	return cfg, nil
}

// validateProposerConfig checks the config holds what charon writes, so every value rendered for the client is set
// and well-formed: a default fee recipient and gas limit, entries of a fee recipient only and numeric builder values.
func validateProposerConfig(cfg proposerconfig.Config) error {
	def := cfg.DefaultConfig

	if def.FeeRecipient == "" {
		return errors.New("default config without fee recipient")
	}

	_, err := eth2util.ValidateChecksumAddress(def.FeeRecipient)
	if err != nil {
		return errors.Wrap(err, "default config fee recipient")
	}

	_, err = parseNumber("gas_limit", def.GasLimit)
	if err != nil {
		return err
	}

	for key, s := range cfg.ProposerConfig {
		if s.GasLimit != "" || s.Builder != nil {
			return errors.New("proposer config entry sets more than fee recipient", z.Str("key", key))
		}

		if s.FeeRecipient == "" {
			continue
		}

		_, err := eth2util.ValidateChecksumAddress(s.FeeRecipient)
		if err != nil {
			return errors.Wrap(err, "proposer config entry fee recipient", z.Str("key", key))
		}
	}

	b := def.Builder
	if b == nil {
		return nil
	}

	for name, value := range map[string]string{"min_bid": b.MinBid, "builder_boost_factor": b.BuilderBoostFactor, "max_execution_payment": b.MaxExecutionPayment} {
		_, err := parseNumber(name, value)
		if err != nil {
			return err
		}
	}

	for i, e := range b.Builders {
		if e.URL == "" {
			return errors.New("builder without url", z.Int("index", i))
		}

		// A signed proposer config holds no per-builder values.
		if e.MinBid != "" || e.BuilderBoostFactor != "" || e.MaxExecutionPayment != "" {
			return errors.New("builder entry sets more than url", z.Int("index", i))
		}
	}

	return nil
}

// writeFile atomically writes data to the path relative to outputDir with the mode, creating its directories. A
// secret's directories up to outputDir are made private, also when they already exist.
func writeFile(outputDir, rel string, data []byte, mode os.FileMode) error {
	path := filepath.Join(outputDir, rel)
	dir := filepath.Dir(path)

	err := os.MkdirAll(dir, 0o755)
	if err != nil {
		return errors.Wrap(err, "create directory", z.Str("path", dir))
	}

	if mode == secretMode {
		for d := filepath.Dir(rel); d != "."; d = filepath.Dir(d) {
			err := os.Chmod(filepath.Join(outputDir, d), 0o700)
			if err != nil {
				return errors.Wrap(err, "chmod directory", z.Str("path", d))
			}
		}
	}

	return proposerconfig.WriteAtomic(path, data, mode)
}
