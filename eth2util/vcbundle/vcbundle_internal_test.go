// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package vcbundle

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
)

// testPubkeyA and testPubkeyB are the public keys of the test keystores.
const (
	testPubkeyA = "0xaa1100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	testPubkeyB = "0xbb2200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
)

// upperPubkeyA is testPubkeyA in uppercase hex.
var upperPubkeyA = "0x" + strings.ToUpper(testPubkeyA[2:])

func TestClientVersions(t *testing.T) {
	for _, client := range clients {
		require.NotEmpty(t, clientVersions[client], client)
	}

	require.Len(t, clientVersions, len(clients))
}

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
		{Prysm, []string{"prysm-proposer-settings.json", "prysm-wallet/direct/accounts/all-accounts.keystore.json", "prysm-wallet/walletpassword.txt", "vc-flags.txt"}},
		{Lodestar, []string{"keystores/" + testPubkeyA + "/voting-keystore.json", "keystores/" + testPubkeyB + "/voting-keystore.json", "lodestar-proposer-settings.yml", "secrets/" + testPubkeyA, "secrets/" + testPubkeyB, "vc-flags.txt"}},
		{Nimbus, []string{
			"secrets/" + testPubkeyA, "secrets/" + testPubkeyB,
			"validators/" + testPubkeyA + "/keystore.json", "validators/" + testPubkeyA + "/suggested_fee_recipient.hex", "validators/" + testPubkeyA + "/suggested_gas_limit.json",
			"validators/" + testPubkeyB + "/keystore.json", "validators/" + testPubkeyB + "/suggested_fee_recipient.hex", "validators/" + testPubkeyB + "/suggested_gas_limit.json",
			"vc-flags.txt",
		}},
		{Lighthouse, []string{
			"secrets/" + testPubkeyA, "secrets/" + testPubkeyB,
			"validators/" + testPubkeyA + "/voting-keystore.json", "validators/" + testPubkeyB + "/voting-keystore.json",
			"validators/builder_definitions.yml", "validators/validator_definitions.yml", "vc-flags.txt",
		}},
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

		requireFile(t, conf.OutputDir, "validators/"+testPubkeyA+"/suggested_fee_recipient.hex", "0x000000000000000000000000000000000000beef\n")
		requireFile(t, conf.OutputDir, "validators/"+testPubkeyB+"/suggested_fee_recipient.hex", "0x000000000000000000000000000000000000dead\n")
		requireFile(t, conf.OutputDir, "validators/"+testPubkeyB+"/suggested_gas_limit.json", "60000000\n")
		requireFile(t, conf.OutputDir, "vc-flags.txt", "--distributed\n--doppelganger-detection=false\n--payload-builder=true\n"+
			"--payload-builder-url=https://builder-a.example.com\n--builder-min-bid=1\n--builder-boost-factor=90\n--builder-max-execution-payment=5\n")
	})

	t.Run("lodestar", func(t *testing.T) {
		conf := testBundle(t, Lodestar)
		_, err := Write(t.Context(), conf)
		require.NoError(t, err)

		requireFile(t, conf.OutputDir, "secrets/"+testPubkeyA, "password-0")

		info, err := os.Stat(filepath.Join(conf.OutputDir, "secrets", testPubkeyA))
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

		info, err = os.Stat(filepath.Join(conf.OutputDir, "secrets"))
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o700), info.Mode().Perm())

		keystore, err := os.ReadFile(filepath.Join(conf.ValidatorKeysDir, "keystore-1.json"))
		require.NoError(t, err)
		requireFile(t, conf.OutputDir, "keystores/"+testPubkeyB+"/voting-keystore.json", string(keystore))
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
		require.Len(t, got, 2)
	})

	t.Run("lighthouse keystores only", func(t *testing.T) {
		conf := testBundle(t, Lighthouse)
		conf.Parts = []Part{PartKeystores}
		conf.LighthouseDir = ""

		got, err := Write(t.Context(), conf)
		require.NoError(t, err)
		require.Len(t, got, 4)
		require.NoFileExists(t, filepath.Join(conf.OutputDir, "validators", "validator_definitions.yml"))
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
	t.Run("keystores copied", func(t *testing.T) {
		conf := testBundle(t, Lighthouse)

		_, err := Write(t.Context(), conf)
		require.NoError(t, err)

		keystore, err := os.ReadFile(filepath.Join(conf.ValidatorKeysDir, "keystore-0.json"))
		require.NoError(t, err)
		requireFile(t, conf.OutputDir, "validators/"+testPubkeyA+"/voting-keystore.json", string(keystore))
		requireFile(t, conf.OutputDir, "secrets/"+testPubkeyA, "password-0")

		b, err := os.ReadFile(filepath.Join(conf.OutputDir, "validators", "validator_definitions.yml"))
		require.NoError(t, err)
		require.Contains(t, string(b), `voting_keystore_path: "/root/.lighthouse/hoodi/validators/`+testPubkeyA+`/voting-keystore.json"`)
		require.Contains(t, string(b), `voting_keystore_password_path: "/root/.lighthouse/hoodi/secrets/`+testPubkeyA+`"`)
		require.NotContains(t, string(b), conf.ValidatorKeysDir)
	})

	for name, dir := range map[string]string{"no lighthouse dir": "", "relative lighthouse dir": "lighthouse"} {
		t.Run(name, func(t *testing.T) {
			conf := testBundle(t, Lighthouse)
			conf.LighthouseDir = dir

			_, err := Write(t.Context(), conf)
			require.ErrorContains(t, err, "absolute data directory")
			require.NoDirExists(t, conf.OutputDir)
		})
	}

	t.Run("builder removed", func(t *testing.T) {
		conf := testBundle(t, Lighthouse)
		_, err := Write(t.Context(), conf)
		require.NoError(t, err)
		require.FileExists(t, filepath.Join(conf.OutputDir, "validators", "builder_definitions.yml"))

		writeTestProposerConfig(t, conf.ProposerConfigFile, testConfig(false))

		conf.Parts = []Part{PartProposerSettings, PartVCFlags}
		got, err := Write(t.Context(), conf)
		require.NoError(t, err)
		require.Equal(t, []string{"validators/builder_definitions.yml", "validators/validator_definitions.yml", "vc-flags.txt"}, got)

		builders, err := os.ReadFile(filepath.Join(conf.OutputDir, "validators", "builder_definitions.yml"))
		require.NoError(t, err)
		require.JSONEq(t, `{"min_bid": 0, "builder_boost_factor": 100, "builders": []}`, string(builders))
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
	requireFile(t, conf.OutputDir, "validators/"+testPubkeyB+"/suggested_fee_recipient.hex", "0x000000000000000000000000000000000000f00d\n")
	requireFile(t, conf.OutputDir, "validators/"+testPubkeyA+"/suggested_fee_recipient.hex", "0x000000000000000000000000000000000000beef\n")
}

// testBundle returns the config of a bundle of all parts for a node with two keystores and a proposer config with
// a builder block.
func testBundle(t *testing.T, client Client) Config {
	t.Helper()

	nodeDir := t.TempDir()
	keysDir := filepath.Join(nodeDir, "validator_keys")
	require.NoError(t, os.Mkdir(keysDir, 0o700))

	// Only prysm decrypts the keystores.
	if client == Prysm {
		writeEncryptedTestKeystores(t, keysDir, 2)
	} else {
		writeTestKeystore(t, keysDir, 0, testPubkeyA[2:])
		writeTestKeystore(t, keysDir, 1, testPubkeyB[2:])
	}

	proposerConfigFile := filepath.Join(nodeDir, "vc-config", "proposer-config.json")
	writeTestProposerConfig(t, proposerConfigFile, testConfig(true))

	return Config{
		Client:             client,
		Parts:              AllParts(),
		OutputDir:          filepath.Join(nodeDir, "vc-bundle"),
		ProposerConfigFile: proposerConfigFile,
		ValidatorKeysDir:   keysDir,
		LighthouseDir:      "/root/.lighthouse/hoodi",
	}
}

// writeTestProposerConfig writes a signed-looking proposer config file holding cfg.
func writeTestProposerConfig(t *testing.T, path string, cfg proposerconfig.Config) {
	t.Helper()

	doc := proposerconfig.Document{Version: proposerconfig.Version, LockHash: bytes.Repeat([]byte{1}, 32), Revision: 1, Config: cfg}

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
	cfg.ProposerConfig = map[string]proposerconfig.Settings{upperPubkeyA: cfg.ProposerConfig[testPubkeyA]}
	writeTestProposerConfig(t, conf.ProposerConfigFile, cfg)

	_, err := Write(t.Context(), conf)
	require.NoError(t, err)
	requireFile(t, conf.OutputDir, "validators/"+testPubkeyA+"/suggested_fee_recipient.hex", "0x000000000000000000000000000000000000beef\n")

	conf.Client = Teku
	_, err = Write(t.Context(), conf)
	require.NoError(t, err)

	b, err := os.ReadFile(filepath.Join(conf.OutputDir, "teku-proposer-config.json"))
	require.NoError(t, err)
	require.Contains(t, string(b), `"`+testPubkeyA+`": {`)
	require.NotContains(t, string(b), upperPubkeyA)
	require.Contains(t, string(b), "beef")

	t.Run("colliding keys", func(t *testing.T) {
		cfg.ProposerConfig[testPubkeyA] = proposerconfig.Settings{FeeRecipient: "0x000000000000000000000000000000000000f00d"}
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

	for _, dir := range []string{"validators", "validators/" + testPubkeyA, "secrets"} {
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
		{name: "teku", client: Teku, want: []string{"Builders taken from the proposer config file", "teku-proposer-config.json", "builder-a.example.com", "builder-b.example.com"}},
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

	// The builders are logged with the part holding them: the settings file, or the flags for nimbus.
	parts := []struct {
		name   string
		client Client
		parts  []Part
		logged bool
	}{
		{name: "teku settings only", client: Teku, parts: []Part{PartProposerSettings}, logged: true},
		{name: "teku flags only", client: Teku, parts: []Part{PartVCFlags}},
		{name: "nimbus settings only", client: Nimbus, parts: []Part{PartProposerSettings}},
		{name: "nimbus flags only", client: Nimbus, parts: []Part{PartVCFlags}, logged: true},
		{name: "keystores only", client: Teku, parts: []Part{PartKeystores}},
	}
	for _, test := range parts {
		t.Run(test.name, func(t *testing.T) {
			conf := testBundle(t, test.client)
			conf.Parts = test.parts

			var buf bytes.Buffer

			ctx := log.WithLogger(context.Background(), log.NewConsoleForT(t, zapcore.AddSync(&buf)))

			_, err := Write(ctx, conf)
			require.NoError(t, err)
			require.Equal(t, test.logged, strings.Contains(buf.String(), "uilder"), buf.String())
		})
	}
}

// TestWriteInvalidProposerConfig verifies a proposer config file edited by hand into an invalid one is rejected.
func TestWriteInvalidProposerConfig(t *testing.T) {
	const (
		defaultRecipient = `"0x000000000000000000000000000000000000dead"`
		entryRecipient   = `"0x000000000000000000000000000000000000beef"`
	)

	tests := []struct {
		name    string
		old     string
		new     string
		wantErr string
	}{
		{name: "version", old: `"version": "v1.0.0"`, new: `"version": "v2.0.0"`, wantErr: "unsupported proposer config file version"},
		{name: "no default fee recipient", old: defaultRecipient, new: `""`, wantErr: "default config without fee recipient"},
		{name: "default fee recipient", old: defaultRecipient, new: `"0xdead"`, wantErr: "default config fee recipient"},
		{name: "no gas limit", old: `"gas_limit": "60000000"`, new: `"gas_limit": ""`, wantErr: "parse gas_limit"},
		{name: "entry fee recipient", old: entryRecipient, new: `"beef"`, wantErr: "proposer config entry fee recipient"},
		{name: "entry gas limit", old: `"fee_recipient": ` + entryRecipient, new: `"gas_limit": "1"`, wantErr: "proposer config entry sets more than fee recipient"},
		{name: "no max execution payment", old: `"max_execution_payment": "5"`, new: `"max_execution_payment": ""`, wantErr: "parse max_execution_payment"},
		{name: "min bid", old: `"min_bid": "1"`, new: `"min_bid": "x"`, wantErr: "parse min_bid"},
		{name: "builder without url", old: `"url": "https://builder-a.example.com"`, new: `"url": ""`, wantErr: "builder without url"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conf := testBundle(t, Nimbus)

			b, err := os.ReadFile(conf.ProposerConfigFile)
			require.NoError(t, err)
			require.Contains(t, string(b), test.old)
			require.NoError(t, os.WriteFile(conf.ProposerConfigFile, []byte(strings.Replace(string(b), test.old, test.new, 1)), 0o644))

			_, err = Write(t.Context(), conf)
			require.ErrorContains(t, err, test.wantErr)
			require.NoDirExists(t, conf.OutputDir)
		})
	}
}

func TestWriteLogsKeystores(t *testing.T) {
	tests := []struct {
		client Client
		want   []string
	}{
		{Teku, []string{"Validator client bundle made for client version", `"client": "teku"`, `"version": "develop"`, "Keystores copied, teku reads the keystore and password pairs", `"dir": "keystores"`, `"keystores": 2`}},
		{Prysm, []string{"Keystores decrypted into a prysm wallet", `"wallet_dir": "prysm-wallet"`, `"keystores": 2`}},
		{Lodestar, []string{"Keystores written in lodestar's layout", `"keystores_dir": "keystores"`, `"secrets_dir": "secrets"`}},
		{Nimbus, []string{"Keystores written in nimbus's layout", `"keystores_dir": "validators"`, `"secrets_dir": "secrets"`}},
		{Lighthouse, []string{"Keystores written in lighthouse's layout", `"keystores_dir": "validators"`, `"secrets_dir": "secrets"`}},
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
