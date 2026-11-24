// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster/proposerconfig"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/eth2util/vcbundle"
	"github.com/obolnetwork/charon/tbls"
)

func TestValidatorCmd(t *testing.T) {
	run := func(t *testing.T, args ...string) (vcbundle.Config, error) {
		t.Helper()

		var got vcbundle.Config

		runFunc := func(_ context.Context, _ io.Writer, conf vcbundle.Config) error {
			got = conf
			return nil
		}

		cmd := newValidatorCmd(newValidatorConfigCmd(runFunc), newValidatorKeysCmd(runFunc))
		cmd.SetArgs(args)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)

		return got, cmd.Execute()
	}

	t.Run("config defaults", func(t *testing.T) {
		got, err := run(t, "config", "nimbus")
		require.NoError(t, err)
		require.Equal(t, vcbundle.Config{
			Client:             vcbundle.Nimbus,
			OutputDir:          ".charon/validator-config/nimbus",
			ProposerConfigFile: ".charon/vc-config/proposer-config.json",
			ValidatorKeysDir:   ".charon/validator_keys",
		}, got)
	})

	t.Run("keys defaults", func(t *testing.T) {
		got, err := run(t, "keys", "nimbus")
		require.NoError(t, err)
		require.Equal(t, vcbundle.Config{
			Client:           vcbundle.Nimbus,
			OutputDir:        ".charon/validator_keys/nimbus",
			ValidatorKeysDir: ".charon/validator_keys",
		}, got)
	})

	t.Run("keys beside the key shares", func(t *testing.T) {
		got, err := run(t, "keys", "teku", "--validator-keys-dir=/node/validator_keys")
		require.NoError(t, err)
		require.Equal(t, "/node/validator_keys/teku", got.OutputDir)
	})

	t.Run("output and lighthouse dir", func(t *testing.T) {
		got, err := run(t, "config", "lighthouse", "--output-dir=/out", "--lighthouse-dir=/root/.lighthouse/hoodi")
		require.NoError(t, err)
		require.Equal(t, "/out", got.OutputDir)
		require.Equal(t, "/root/.lighthouse/hoodi", got.LighthouseDir)
	})

	t.Run("builder api", func(t *testing.T) {
		got, err := run(t, "config", "teku", "--builder-api")
		require.NoError(t, err)
		require.True(t, got.BuilderAPI)
	})

	tests := map[string][]string{
		"config no client":      {"config"},
		"config unknown client": {"config", "vero"},
		"config two clients":    {"config", "teku", "prysm"},
		"keys no client":        {"keys"},
		"keys unknown client":   {"keys", "vero"},
		"keys no proposer file": {"keys", "teku", "--proposer-config-file=x"},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, args...)
			require.Error(t, err)
		})
	}
}

func TestRunValidator(t *testing.T) {
	lighthousePubkey := "0xaa11" + strings.Repeat("0", 92)

	nodeDir := t.TempDir()
	keysDir := filepath.Join(nodeDir, "validator_keys")
	require.NoError(t, os.Mkdir(keysDir, 0o700))

	for i, pubkey := range []string{lighthousePubkey[2:], "bb22" + strings.Repeat("0", 92)} {
		keystore := fmt.Sprintf(`{"pubkey":%q,"crypto":{},"version":4}`, pubkey)
		require.NoError(t, os.WriteFile(filepath.Join(keysDir, fmt.Sprintf("keystore-%d.json", i)), []byte(keystore), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(keysDir, fmt.Sprintf("keystore-%d.txt", i)), []byte("password"), 0o600))
	}

	doc := proposerconfig.Document{
		Version:  proposerconfig.Version,
		LockHash: bytes.Repeat([]byte{1}, 32),
		Revision: 1,
		Config: proposerconfig.Config{DefaultConfig: proposerconfig.Settings{
			FeeRecipient: "0x000000000000000000000000000000000000dead",
			GasLimit:     "60000000",
			Builder: &proposerconfig.Builder{
				MinBid: "0", BuilderBoostFactor: "100", MaxExecutionPayment: "0",
				Builders: []proposerconfig.BuilderEntry{{URL: "https://builder.example.com"}},
			},
		}},
	}

	b, err := proposerconfig.Marshal(doc)
	require.NoError(t, err)

	proposerConfigFile := filepath.Join(nodeDir, "proposer-config.json")
	require.NoError(t, os.WriteFile(proposerConfigFile, b, 0o644))

	conf := func(client vcbundle.Client) vcbundle.Config {
		return vcbundle.Config{
			Client:             client,
			OutputDir:          filepath.Join(nodeDir, "output-"+string(client)),
			ProposerConfigFile: proposerConfigFile,
			ValidatorKeysDir:   keysDir,
			LighthouseDir:      "/root/.lighthouse/hoodi",
		}
	}

	t.Run("teku config", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, runValidatorConfig(t.Context(), &buf, conf(vcbundle.Teku)))

		out := buf.String()
		require.Contains(t, out, "Proposer settings and flags for teku written to")
		require.Contains(t, out, "  teku-proposer-config.json\n")
		require.Contains(t, out, "  vc-flags.txt\n")
		require.NotContains(t, out, "keystore")
		require.True(t, strings.HasSuffix(out, "Append the lines of vc-flags.txt to the validator client's command.\n"), out)
	})

	t.Run("lighthouse config", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, runValidatorConfig(t.Context(), &buf, conf(vcbundle.Lighthouse)))
		require.Contains(t, buf.String(), "  validators/validator_definitions.yml\n")
		require.Contains(t, buf.String(), "The definitions name the keystores under /root/.lighthouse/hoodi, move the validators and secrets directories there.\n")
	})

	t.Run("lighthouse keys", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, runValidatorKeys(t.Context(), &buf, conf(vcbundle.Lighthouse)))
		require.Contains(t, buf.String(), "Key shares for lighthouse written to")
		require.Contains(t, buf.String(), "  validators/"+lighthousePubkey+"/voting-keystore.json\n")
		require.Contains(t, buf.String(), "  secrets/"+lighthousePubkey+"\n")
		require.NotContains(t, buf.String(), "The definitions name the keystores")
	})

	t.Run("prysm keys", func(t *testing.T) {
		c := conf(vcbundle.Prysm)
		c.ValidatorKeysDir = t.TempDir()

		secret, err := tbls.GenerateSecretKey()
		require.NoError(t, err)
		require.NoError(t, keystore.StoreKeysInsecure([]tbls.PrivateKey{secret}, c.ValidatorKeysDir, keystore.ConfirmInsecureKeys))

		var buf bytes.Buffer
		require.NoError(t, runValidatorKeys(t.Context(), &buf, c))
		require.Contains(t, buf.String(), "  prysm-wallet/direct/accounts/all-accounts.keystore.json\n")
		require.Contains(t, buf.String(), "Point prysm's --wallet-dir at the prysm-wallet directory, no import needed.\n")
	})
}
