// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package vcbundle

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
)

func TestParseClient(t *testing.T) {
	c, err := ParseClient("teku")
	require.NoError(t, err)
	require.Equal(t, Teku, c)

	_, err = ParseClient("vero")
	require.ErrorContains(t, err, "unknown validator client")
	require.ErrorContains(t, err, "teku, prysm, lodestar, nimbus, lighthouse")
}

func TestParseParts(t *testing.T) {
	parts, err := ParseParts([]string{"vc-flags", "keystores", "vc-flags"})
	require.NoError(t, err)
	require.Equal(t, []Part{PartKeystores, PartVCFlags}, parts)

	_, err = ParseParts([]string{"readme"})
	require.ErrorContains(t, err, "keystores, proposer-settings, vc-flags")

	_, err = ParseParts(nil)
	require.ErrorContains(t, err, "nothing to write")
}

func TestWrite(t *testing.T) {
	tests := []struct {
		client Client
		want   []string
	}{
		{Teku, []string{"keystores/keystore-0.json", "keystores/keystore-0.txt", "keystores/keystore-1.json", "keystores/keystore-1.txt", "teku-proposer-config.json", "vc-flags.txt"}},
		{Prysm, []string{"keystores/keystore-0.json", "keystores/keystore-0.txt", "keystores/keystore-1.json", "keystores/keystore-1.txt", "prysm-proposer-settings.json", "vc-flags.txt"}},
		{Lodestar, []string{"keystores/0xaa11/voting-keystore.json", "keystores/0xbb22/voting-keystore.json", "lodestar-proposer-settings.yml", "secrets/0xaa11", "secrets/0xbb22", "vc-flags.txt"}},
		{Nimbus, []string{
			"secrets/0xaa11", "secrets/0xbb22",
			"validators/0xaa11/keystore.json", "validators/0xaa11/suggested_fee_recipient.hex", "validators/0xaa11/suggested_gas_limit.json",
			"validators/0xbb22/keystore.json", "validators/0xbb22/suggested_fee_recipient.hex", "validators/0xbb22/suggested_gas_limit.json",
			"vc-flags.txt",
		}},
		{Lighthouse, []string{"validators/builder_definitions.yml", "validators/validator_definitions.yml", "vc-flags.txt"}},
	}
	for _, test := range tests {
		t.Run(string(test.client), func(t *testing.T) {
			conf := testBundle(t, test.client)

			got, err := Write(t.Context(), conf)
			require.NoError(t, err)
			require.Equal(t, test.want, got)

			for _, file := range got {
				require.FileExists(t, filepath.Join(conf.OutputDir, file))
			}
		})
	}
}

func TestWriteContent(t *testing.T) {
	t.Run("nimbus", func(t *testing.T) {
		conf := testBundle(t, Nimbus)
		_, err := Write(t.Context(), conf)
		require.NoError(t, err)

		requireFile(t, conf.OutputDir, "validators/0xaa11/suggested_fee_recipient.hex", "0x000000000000000000000000000000000000beef\n")
		requireFile(t, conf.OutputDir, "validators/0xbb22/suggested_fee_recipient.hex", "0x000000000000000000000000000000000000dead\n")
		requireFile(t, conf.OutputDir, "validators/0xbb22/suggested_gas_limit.json", "60000000\n")
		requireFile(t, conf.OutputDir, "vc-flags.txt", "--distributed\n--doppelganger-detection=false\n--payload-builder=true\n"+
			"--payload-builder-url=https://builder-a.example.com\n--builder-min-bid=1\n--builder-boost-factor=90\n--builder-max-execution-payment=5\n")
	})

	t.Run("lodestar", func(t *testing.T) {
		conf := testBundle(t, Lodestar)
		_, err := Write(t.Context(), conf)
		require.NoError(t, err)

		requireFile(t, conf.OutputDir, "secrets/0xaa11", "password-0")

		info, err := os.Stat(filepath.Join(conf.OutputDir, "secrets", "0xaa11"))
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

		info, err = os.Stat(filepath.Join(conf.OutputDir, "secrets"))
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o700), info.Mode().Perm())

		keystore, err := os.ReadFile(filepath.Join(conf.ValidatorKeysDir, "keystore-1.json"))
		require.NoError(t, err)
		requireFile(t, conf.OutputDir, "keystores/0xbb22/voting-keystore.json", string(keystore))
	})
}

func TestWriteParts(t *testing.T) {
	t.Run("flags only", func(t *testing.T) {
		conf := testBundle(t, Teku)
		conf.Parts = []Part{PartVCFlags}
		conf.ValidatorKeysDir = filepath.Join(t.TempDir(), "missing")

		got, err := Write(t.Context(), conf)
		require.NoError(t, err)
		require.Equal(t, []string{"vc-flags.txt"}, got)
	})

	t.Run("keystores only", func(t *testing.T) {
		conf := testBundle(t, Prysm)
		conf.Parts = []Part{PartKeystores}
		conf.ProposerConfigFile = filepath.Join(t.TempDir(), "missing.json")

		got, err := Write(t.Context(), conf)
		require.NoError(t, err)
		require.Len(t, got, 4)
	})

	t.Run("lighthouse keystores only", func(t *testing.T) {
		conf := testBundle(t, Lighthouse)
		conf.Parts = []Part{PartKeystores}

		got, err := Write(t.Context(), conf)
		require.NoError(t, err)
		require.Empty(t, got)
		require.NoDirExists(t, filepath.Join(conf.OutputDir, "validators"))
	})

	t.Run("missing proposer config", func(t *testing.T) {
		conf := testBundle(t, Teku)
		conf.ProposerConfigFile = filepath.Join(t.TempDir(), "missing.json")

		_, err := Write(t.Context(), conf)
		require.ErrorContains(t, err, "charon run writes it on start")
		require.NoDirExists(t, conf.OutputDir)
	})
}

func TestWriteLighthouse(t *testing.T) {
	t.Run("absolute keystore paths", func(t *testing.T) {
		conf := testBundle(t, Lighthouse)
		absKeysDir := conf.ValidatorKeysDir

		t.Chdir(filepath.Dir(absKeysDir))
		conf.ValidatorKeysDir = filepath.Base(absKeysDir)

		_, err := Write(t.Context(), conf)
		require.NoError(t, err)

		b, err := os.ReadFile(filepath.Join(conf.OutputDir, "validators", "validator_definitions.yml"))
		require.NoError(t, err)

		// The temp directory may be a symlink, so compare with the path as the test sees it.
		wd, err := os.Getwd()
		require.NoError(t, err)
		require.Contains(t, string(b), `voting_keystore_path: "`+filepath.Join(wd, conf.ValidatorKeysDir, "keystore-0.json")+`"`)
		require.Contains(t, string(b), `voting_keystore_password_path: "`+filepath.Join(wd, conf.ValidatorKeysDir, "keystore-0.txt")+`"`)
	})

	t.Run("builder removed", func(t *testing.T) {
		conf := testBundle(t, Lighthouse)
		_, err := Write(t.Context(), conf)
		require.NoError(t, err)
		require.FileExists(t, filepath.Join(conf.OutputDir, "validators", "builder_definitions.yml"))

		writeTestProposerConfig(t, conf.ProposerConfigFile, testConfig(false))

		got, err := Write(t.Context(), conf)
		require.NoError(t, err)
		require.Equal(t, []string{"validators/validator_definitions.yml", "vc-flags.txt"}, got)
		require.NoFileExists(t, filepath.Join(conf.OutputDir, "validators", "builder_definitions.yml"))
		requireFile(t, conf.OutputDir, "vc-flags.txt", "--distributed\n")

		b, err := os.ReadFile(filepath.Join(conf.OutputDir, "validators", "validator_definitions.yml"))
		require.NoError(t, err)
		require.Contains(t, string(b), "builder_proposals: false")
		require.NotContains(t, string(b), "builder_proposals: true")
	})
}

func TestWriteRewrite(t *testing.T) {
	conf := testBundle(t, Nimbus)
	_, err := Write(t.Context(), conf)
	require.NoError(t, err)

	cfg := testConfig(true)
	cfg.DefaultConfig.FeeRecipient = "0x000000000000000000000000000000000000f00d"
	writeTestProposerConfig(t, conf.ProposerConfigFile, cfg)

	_, err = Write(t.Context(), conf)
	require.NoError(t, err)
	requireFile(t, conf.OutputDir, "validators/0xbb22/suggested_fee_recipient.hex", "0x000000000000000000000000000000000000f00d\n")
	requireFile(t, conf.OutputDir, "validators/0xaa11/suggested_fee_recipient.hex", "0x000000000000000000000000000000000000beef\n")
}

// testBundle returns the config of a bundle of all parts for a node with two keystores and a proposer config with
// a builder block.
func testBundle(t *testing.T, client Client) Config {
	t.Helper()

	nodeDir := t.TempDir()
	keysDir := filepath.Join(nodeDir, "validator_keys")
	require.NoError(t, os.Mkdir(keysDir, 0o700))
	writeTestKeystore(t, keysDir, 0, "aa11")
	writeTestKeystore(t, keysDir, 1, "bb22")

	proposerConfigFile := filepath.Join(nodeDir, "vc-config", "proposer-config.json")
	writeTestProposerConfig(t, proposerConfigFile, testConfig(true))

	return Config{
		Client:             client,
		Parts:              AllParts(),
		OutputDir:          filepath.Join(nodeDir, "vc-bundle"),
		ProposerConfigFile: proposerConfigFile,
		ValidatorKeysDir:   keysDir,
	}
}

// writeTestProposerConfig writes a signed-looking proposer config file holding cfg.
func writeTestProposerConfig(t *testing.T, path string, cfg proposerconfig.Config) {
	t.Helper()

	doc := proposerconfig.Document{Version: proposerconfig.Version, LockHash: []byte{1, 2, 3}, Revision: 1, Config: cfg}

	b, err := proposerconfig.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, b, 0o644))
}

// requireFile checks the file at the path relative to dir holds want.
func requireFile(t *testing.T, dir, path, want string) {
	t.Helper()

	b, err := os.ReadFile(filepath.Join(dir, path))
	require.NoError(t, err)
	require.Equal(t, want, string(b))
}

func TestWriteMixedCaseProposerConfigKeys(t *testing.T) {
	conf := testBundle(t, Nimbus)

	cfg := testConfig(true)
	cfg.ProposerConfig = map[string]proposerconfig.Settings{"0xAA11": cfg.ProposerConfig["0xaa11"]}
	writeTestProposerConfig(t, conf.ProposerConfigFile, cfg)

	_, err := Write(t.Context(), conf)
	require.NoError(t, err)
	requireFile(t, conf.OutputDir, "validators/0xaa11/suggested_fee_recipient.hex", "0x000000000000000000000000000000000000beef\n")

	conf.Client = Teku
	_, err = Write(t.Context(), conf)
	require.NoError(t, err)

	b, err := os.ReadFile(filepath.Join(conf.OutputDir, "teku-proposer-config.json"))
	require.NoError(t, err)
	require.Contains(t, string(b), `"0xaa11": {`)
	require.NotContains(t, string(b), "0xAA11")
	require.Contains(t, string(b), "beef")

	t.Run("colliding keys", func(t *testing.T) {
		cfg.ProposerConfig["0xaa11"] = proposerconfig.Settings{GasLimit: "1"}
		writeTestProposerConfig(t, conf.ProposerConfigFile, cfg)

		_, err := Write(t.Context(), conf)
		require.ErrorContains(t, err, "duplicate proposer config key")
	})
}

func TestWriteSecretDirectoryMode(t *testing.T) {
	conf := testBundle(t, Nimbus)

	// Settings first create the validator directories, a later run adds the keystores to them.
	conf.Parts = []Part{PartProposerSettings}
	_, err := Write(t.Context(), conf)
	require.NoError(t, err)

	conf.Parts = AllParts()
	_, err = Write(t.Context(), conf)
	require.NoError(t, err)

	for _, dir := range []string{"validators", "validators/0xaa11", "secrets"} {
		info, err := os.Stat(filepath.Join(conf.OutputDir, dir))
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o700), info.Mode().Perm(), dir)
	}
}

func TestWriteLogsBuilders(t *testing.T) {
	tests := []struct {
		name    string
		client  Client
		noBuild bool
		want    []string
	}{
		{name: "teku", client: Teku, want: []string{"Builders passed as flags", "vc-flags.txt", "builder-a.example.com", "builder-b.example.com"}},
		{name: "nimbus", client: Nimbus, want: []string{"First builder passed as flags", "vc-flags.txt", "Nimbus takes a single builder", "builder-b.example.com"}},
		{name: "prysm", client: Prysm, want: []string{"Builders taken from the proposer settings file", "prysm-proposer-settings.json"}},
		{name: "lodestar", client: Lodestar, want: []string{"Builders taken from the proposer settings file", "lodestar-proposer-settings.yml"}},
		{name: "lighthouse", client: Lighthouse, want: []string{"Builders taken from the builder definitions", "validators/builder_definitions.yml"}},
		{name: "no builders", client: Lodestar, noBuild: true, want: []string{"No builders in the proposer config"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conf := testBundle(t, test.client)

			cfg := testConfig(!test.noBuild)
			if !test.noBuild {
				cfg.DefaultConfig.Builder.Builders[0].URL = "https://user:secret@builder-a.example.com"
			}

			writeTestProposerConfig(t, conf.ProposerConfigFile, cfg)

			var buf bytes.Buffer

			ctx := log.WithLogger(context.Background(), log.NewConsoleForT(t, zapcore.AddSync(&buf)))

			_, err := Write(ctx, conf)
			require.NoError(t, err)

			for _, want := range test.want {
				require.Contains(t, buf.String(), want)
			}

			require.NotContains(t, buf.String(), "user:secret@")
		})
	}

	t.Run("without flags", func(t *testing.T) {
		conf := testBundle(t, Teku)
		conf.Parts = []Part{PartKeystores, PartProposerSettings}

		var buf bytes.Buffer

		ctx := log.WithLogger(context.Background(), log.NewConsoleForT(t, zapcore.AddSync(&buf)))

		_, err := Write(ctx, conf)
		require.NoError(t, err)
		require.NotContains(t, buf.String(), "uilder")
	})
}

func TestWriteLogsKeystores(t *testing.T) {
	tests := []struct {
		client Client
		want   []string
	}{
		{Teku, []string{"Keystores copied, teku reads the keystore and password pairs", `"dir": "keystores"`, `"keystores": 2`}},
		{Prysm, []string{"Keystores copied for prysm's wallet import", `"dir": "keystores"`, `"keystores": 2`}},
		{Lodestar, []string{"Keystores written in lodestar's layout", `"keystores_dir": "keystores"`, `"secrets_dir": "secrets"`}},
		{Nimbus, []string{"Keystores written in nimbus's layout", `"keystores_dir": "validators"`, `"secrets_dir": "secrets"`}},
		{Lighthouse, []string{"Keystores read in place by lighthouse", "validator_keys"}},
	}
	for _, test := range tests {
		t.Run(string(test.client), func(t *testing.T) {
			conf := testBundle(t, test.client)
			conf.Parts = []Part{PartKeystores}

			var buf bytes.Buffer

			ctx := log.WithLogger(context.Background(), log.NewConsoleForT(t, zapcore.AddSync(&buf)))

			_, err := Write(ctx, conf)
			require.NoError(t, err)

			for _, want := range test.want {
				require.Contains(t, buf.String(), want)
			}
		})
	}
}
