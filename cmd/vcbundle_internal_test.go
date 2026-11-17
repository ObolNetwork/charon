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

func TestVCBundleCmd(t *testing.T) {
	run := func(t *testing.T, args ...string) (vcbundle.Config, error) {
		t.Helper()

		var got vcbundle.Config

		cmd := newVCBundleCmd(func(_ context.Context, _ io.Writer, conf vcbundle.Config) error {
			got = conf
			return nil
		})
		cmd.SetArgs(args)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)

		return got, cmd.Execute()
	}

	t.Run("lighthouse dir", func(t *testing.T) {
		got, err := run(t, "lighthouse", "--lighthouse-dir=/root/.lighthouse/hoodi")
		require.NoError(t, err)
		require.Equal(t, "/root/.lighthouse/hoodi", got.LighthouseDir)
	})

	t.Run("defaults", func(t *testing.T) {
		got, err := run(t, "nimbus")
		require.NoError(t, err)
		require.Equal(t, vcbundle.Config{
			Client:             vcbundle.Nimbus,
			Parts:              vcbundle.AllParts(),
			OutputDir:          ".charon/vc-bundle",
			ProposerConfigFile: ".charon/vc-config/proposer-config.json",
			ValidatorKeysDir:   ".charon/validator_keys",
		}, got)
	})

	t.Run("include", func(t *testing.T) {
		got, err := run(t, "teku", "--include=vc-flags,proposer-settings")
		require.NoError(t, err)
		require.Equal(t, []vcbundle.Part{vcbundle.PartProposerSettings, vcbundle.PartVCFlags}, got.Parts)
	})

	tests := map[string][]string{
		"no client":      nil,
		"unknown client": {"vero"},
		"unknown part":   {"teku", "--include=readme"},
		"two clients":    {"teku", "prysm"},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, args...)
			require.Error(t, err)
		})
	}
}

func TestRunVCBundle(t *testing.T) {
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
		LockHash: []byte{1},
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
			Parts:              vcbundle.AllParts(),
			OutputDir:          filepath.Join(nodeDir, "vc-bundle-"+string(client)),
			ProposerConfigFile: proposerConfigFile,
			ValidatorKeysDir:   keysDir,
			LighthouseDir:      "/root/.lighthouse/hoodi",
		}
	}

	t.Run("teku", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, runVCBundle(t.Context(), &buf, conf(vcbundle.Teku)))

		out := buf.String()
		require.Contains(t, out, "Validator client bundle for teku written to")
		require.Contains(t, out, "  teku-proposer-config.json\n")
		require.Contains(t, out, "  vc-flags.txt\n")
		require.True(t, strings.HasSuffix(out, "Append the lines of vc-flags.txt to the validator client's command.\n"), out)
	})

	t.Run("lighthouse", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, runVCBundle(t.Context(), &buf, conf(vcbundle.Lighthouse)))
		require.Contains(t, buf.String(), "  validators/"+lighthousePubkey+"/voting-keystore.json\n")
		require.Contains(t, buf.String(), "The definitions name the keystores under /root/.lighthouse/hoodi, move the validators and secrets directories there.\n")
	})

	t.Run("prysm", func(t *testing.T) {
		c := conf(vcbundle.Prysm)
		c.ValidatorKeysDir = t.TempDir()

		secret, err := tbls.GenerateSecretKey()
		require.NoError(t, err)
		require.NoError(t, keystore.StoreKeysInsecure([]tbls.PrivateKey{secret}, c.ValidatorKeysDir, keystore.ConfirmInsecureKeys))

		var buf bytes.Buffer
		require.NoError(t, runVCBundle(t.Context(), &buf, c))
		require.Contains(t, buf.String(), "  prysm-wallet/direct/accounts/all-accounts.keystore.json\n")
		require.Contains(t, buf.String(), "Point prysm's --wallet-dir at the prysm-wallet directory, no import needed.\n")
	})

	t.Run("lighthouse keystores only", func(t *testing.T) {
		c := conf(vcbundle.Lighthouse)
		c.Parts = []vcbundle.Part{vcbundle.PartKeystores}
		c.OutputDir = t.TempDir()

		var buf bytes.Buffer
		require.NoError(t, runVCBundle(t.Context(), &buf, c))
		require.Contains(t, buf.String(), "  secrets/"+lighthousePubkey+"\n")
		require.NotContains(t, buf.String(), "The definitions name the keystores")
	})
}
