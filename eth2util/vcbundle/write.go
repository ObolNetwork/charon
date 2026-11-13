// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package vcbundle

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
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

	// A stale builders file must not be moved into Lighthouse.
	if conf.Client == Lighthouse && slices.Contains(conf.Parts, PartProposerSettings) &&
		!slices.ContainsFunc(files, func(f bundleFile) bool { return f.Path == lighthouseBuildersPath }) {
		err := os.Remove(filepath.Join(conf.OutputDir, lighthouseBuildersPath))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, errors.Wrap(err, "remove stale builder definitions")
		}
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

	include := func(p Part) bool { return slices.Contains(conf.Parts, p) }
	perValidator := conf.Client == Nimbus || conf.Client == Lighthouse

	var (
		keystores []keystoreFile
		cfg       proposerconfig.Config
		err       error
	)

	if (include(PartKeystores) && conf.Client != Lighthouse) || (include(PartProposerSettings) && perValidator) {
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

	var files []bundleFile

	if include(PartKeystores) {
		files, err = keystoreFiles(ctx, conf.Client, conf.ValidatorKeysDir, keystores)
		if err != nil {
			return nil, err
		}
	}

	if include(PartProposerSettings) {
		settings, err := proposerConfigFiles(conf.Client, cfg, keystores)
		if err != nil {
			return nil, err
		}

		files = append(files, settings...)
	}

	if include(PartVCFlags) {
		flags, err := vcFlags(ctx, conf.Client, cfg)
		if err != nil {
			return nil, err
		}

		files = append(files, bundleFile{Path: FlagsFile, Data: renderFlags(flags), Mode: publicMode})
	}

	return files, nil
}

// loadProposerConfig returns the config of the proposer config file as charon run writes it, keyed by this node's
// public shares, which are the keystores' public keys.
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

	return cfg, nil
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

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return errors.Wrap(err, "create temp file", z.Str("path", dir))
	}

	cleanup := func(err error, msg string) error {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())

		return errors.Wrap(err, msg, z.Str("path", path))
	}

	_, err = tmp.Write(data)
	if err != nil {
		return cleanup(err, "write temp file")
	}

	err = tmp.Chmod(mode)
	if err != nil {
		return cleanup(err, "chmod temp file")
	}

	err = tmp.Close()
	if err != nil {
		return cleanup(err, "close temp file")
	}

	err = os.Rename(tmp.Name(), path)
	if err != nil {
		return cleanup(err, "rename temp file")
	}

	return nil
}
