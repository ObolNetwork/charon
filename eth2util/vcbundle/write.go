// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package vcbundle

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

// Config configures a validator client bundle.
type Config struct {
	Client             Client
	Parts              []Part
	OutputDir          string
	ProposerConfigFile string
	ValidatorKeysDir   string
	// LighthouseDir is Lighthouse's data directory as Lighthouse sees it, absolute. Its validator definitions name
	// the bundle's keystores under it.
	LighthouseDir string
}

// bundleFile is a file of the bundle, its path relative to the output directory.
type bundleFile struct {
	Path string
	Data []byte
	Mode os.FileMode
}

// Write writes the bundle and returns the paths of the files written, relative to the output directory, sorted.
// Everything is rendered before anything is written.
func Write(ctx context.Context, conf Config) ([]string, error) {
	files, err := render(ctx, conf)
	if err != nil {
		return nil, err
	}

	var resp []string

	for _, f := range files {
		err := writeFile(conf.OutputDir, f.Path, f.Data, f.Mode)
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

// render returns the files of the bundle, keystores first.
func render(ctx context.Context, conf Config) ([]bundleFile, error) {
	if !slices.Contains(clients, conf.Client) {
		return nil, errors.New("unknown validator client, use one of: "+join(clients), z.Str("client", string(conf.Client)))
	}

	if len(conf.Parts) == 0 {
		return nil, errors.New("nothing to write, include at least one of: " + join(AllParts()))
	}

	log.Info(ctx, "Validator client bundle made for client version", z.Str("client", string(conf.Client)), z.Str("version", clientVersions[conf.Client]))

	include := func(p Part) bool { return slices.Contains(conf.Parts, p) }
	perValidator := conf.Client == Prysm || conf.Client == Nimbus || conf.Client == Lighthouse

	if conf.Client == Lighthouse && include(PartProposerSettings) && !path.IsAbs(conf.LighthouseDir) {
		return nil, errors.New("lighthouse's validator definitions need its absolute data directory, as lighthouse sees it",
			z.Str("lighthouse_dir", conf.LighthouseDir))
	}

	var (
		keystores []keystoreFile
		cfg       proposerconfig.Config
		err       error
	)

	if include(PartKeystores) || (include(PartProposerSettings) && perValidator) {
		keystores, err = listKeystores(conf.ValidatorKeysDir)
		if err != nil {
			return nil, err
		}
	}

	if include(PartProposerSettings) || include(PartVCFlags) {
		cfg, err = loadProposerConfig(conf.ProposerConfigFile)
		if err != nil {
			return nil, err
		}
	}

	if include(PartProposerSettings) || include(PartVCFlags) {
		logBuilders(ctx, conf.Client, cfg.DefaultConfig.Builder, include)
	}

	var files []bundleFile

	if include(PartKeystores) {
		files, err = keystoreFiles(ctx, conf.Client, conf.ValidatorKeysDir, keystores)
		if err != nil {
			return nil, err
		}
	}

	if include(PartProposerSettings) {
		settings, err := proposerConfigFiles(conf.Client, cfg, keystores, conf.LighthouseDir)
		if err != nil {
			return nil, err
		}

		files = append(files, settings...)
	}

	if include(PartVCFlags) {
		files = append(files, bundleFile{Path: FlagsFile, Data: renderFlags(vcFlags(conf.Client, cfg)), Mode: publicMode})
	}

	return files, nil
}

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
