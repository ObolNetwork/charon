// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
	"github.com/obolnetwork/charon/dkg"
	"github.com/obolnetwork/charon/eth2util"
)

const (
	editFeeRecipientLower = "0x000000000000000000000000000000000000dead"
	editFeeRecipientSum   = "0x000000000000000000000000000000000000dEaD"
)

func TestProposerEditFlags(t *testing.T) {
	u64 := func(v uint64) *uint64 { return &v }

	tests := []struct {
		name   string
		args   []string
		errMsg string
		delta  proposerconfig.Delta
	}{
		{
			name:   "no change flag",
			args:   []string{},
			errMsg: "no change requested",
		},
		{
			name:   "validators without fee recipient",
			args:   []string{"--fee-recipient-validators=0xabc", "--gas-limit=1"},
			errMsg: "fee-recipient-validators requires fee-recipient",
		},
		{
			name:   "validators with gas limit",
			args:   []string{"--fee-recipient=" + editFeeRecipientLower, "--fee-recipient-validators=0xabc", "--gas-limit=1"},
			errMsg: "fee-recipient-validators can only be combined with fee-recipient",
		},
		{
			name:   "validators with builder flag",
			args:   []string{"--fee-recipient=" + editFeeRecipientLower, "--fee-recipient-validators=0xabc", "--builder-min-bid=1"},
			errMsg: "fee-recipient-validators can only be combined with fee-recipient",
		},
		{
			name:   "validators with no builders",
			args:   []string{"--fee-recipient=" + editFeeRecipientLower, "--fee-recipient-validators=0xabc", "--no-builders"},
			errMsg: "fee-recipient-validators can only be combined with fee-recipient",
		},
		{
			name:   "no builders with builder urls",
			args:   []string{"--no-builders", "--builder-urls=https://a"},
			errMsg: "no-builders excludes",
		},
		{
			name:   "no builders with min bid",
			args:   []string{"--no-builders", "--builder-min-bid=1"},
			errMsg: "no-builders excludes",
		},
		{
			name:   "zero gas limit",
			args:   []string{"--gas-limit=0"},
			errMsg: "gas-limit must be greater than 0",
		},
		{
			name:   "zero boost factor",
			args:   []string{"--builder-urls=https://a", "--builder-boost-factor=0"},
			errMsg: "builder-boost-factor must be greater than 0",
		},
		{
			name:   "empty builder urls",
			args:   []string{"--builder-urls="},
			errMsg: "builder-urls must not be empty",
		},
		{
			name:   "bad checksum",
			args:   []string{"--fee-recipient=0x000000000000000000000000000000000000DEaD"},
			errMsg: "invalid fee-recipient address",
		},
		{
			name:   "zero address",
			args:   []string{"--fee-recipient=" + zeroAddress},
			errMsg: "zero fee-recipient address forbidden",
		},
		{
			name: "fee recipient only",
			args: []string{"--fee-recipient=" + editFeeRecipientLower},
			delta: proposerconfig.Delta{
				FeeRecipient: editFeeRecipientSum,
			},
		},
		{
			name: "validator scoped",
			args: []string{"--fee-recipient=" + editFeeRecipientSum, "--fee-recipient-validators=0xabc,0xdef"},
			delta: proposerconfig.Delta{
				FeeRecipient:           editFeeRecipientSum,
				FeeRecipientValidators: []string{"0xabc", "0xdef"},
			},
		},
		{
			name: "gas limit only leaves builder fields unset",
			args: []string{"--gas-limit=60000000"},
			delta: proposerconfig.Delta{
				GasLimit: 60000000,
			},
		},
		{
			name: "combined",
			args: []string{
				"--fee-recipient=" + editFeeRecipientSum, "--gas-limit=60000000",
				"--builder-urls=https://a,https://b", "--builder-min-bid=5", "--builder-boost-factor=110", "--builder-max-execution-payment=0",
			},
			delta: proposerconfig.Delta{
				FeeRecipient:               editFeeRecipientSum,
				GasLimit:                   60000000,
				BuilderURLs:                []string{"https://a", "https://b"},
				BuilderMinBid:              u64(5),
				BuilderBoostFactor:         u64(110),
				BuilderMaxExecutionPayment: u64(0),
			},
		},
		{
			name:  "no builders",
			args:  []string{"--no-builders"},
			delta: proposerconfig.Delta{NoBuilders: true},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var (
				called bool
				got    dkg.ProposerConfigEditConfig
			)

			cmd := newProposerEditCmd(func(_ context.Context, _ io.Writer, conf dkg.ProposerConfigEditConfig) error {
				called = true
				got = conf

				return nil
			})
			cmd.SetArgs(append(test.args, "--yes"))
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)

			err := cmd.Execute()
			if test.errMsg != "" {
				require.ErrorContains(t, err, test.errMsg)
				require.False(t, called)

				return
			}

			require.NoError(t, err)
			require.True(t, called)
			require.Equal(t, test.delta, got.Delta)
			require.Equal(t, 24*time.Hour, got.DKGConfig.Timeout)
			require.Equal(t, 5*time.Second, got.DKGConfig.ShutdownDelay)
			require.Equal(t, []string{"https://4.relay.obol.dev"}, got.DKGConfig.P2P.Relays)
			require.Equal(t, ".charon/vc-config/proposer-config.json", got.ProposerConfigFile)
			require.Equal(t, ".charon/builder_registrations_overrides.json", got.OverridesFile)
			require.Nil(t, got.ParticipatingENRs)
			require.Nil(t, got.Confirm)
		})
	}
}

func TestProposerEditParticipants(t *testing.T) {
	srcDir := t.TempDir()
	conf := clusterConfig{
		ClusterDir:        srcDir,
		Name:              t.Name(),
		NumNodes:          4,
		Threshold:         3,
		NumDVs:            1,
		Network:           eth2util.Hoodi.Name,
		TargetGasLimit:    36000000,
		FeeRecipientAddrs: []string{feeRecipientAddr},
		WithdrawalAddrs:   []string{feeRecipientAddr},
	}
	require.NoError(t, createClusterT(t.Context(), io.Discard, conf))

	lock, err := dkg.LoadAndVerifyClusterLock(t.Context(), path.Join(nodeDir(srcDir, 0), clusterLockFile), "", true)
	require.NoError(t, err)

	enr := func(i int) string { return lock.Operators[i].ENR }

	tests := []struct {
		name   string
		enrs   []string
		errMsg string
	}{
		{name: "duplicate", enrs: []string{enr(0), enr(1), enr(1)}, errMsg: "duplicate ENRs"},
		{name: "unknown operator", enrs: []string{enr(0), enr(1), "enr:-unknown"}, errMsg: "non-existing operator"},
		{name: "below threshold", enrs: []string{enr(0), enr(1)}, errMsg: "at least the threshold"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var buf bytes.Buffer

			err := runProposerEdit(t.Context(), &buf, dkg.ProposerConfigEditConfig{
				LockFilePath:      path.Join(nodeDir(srcDir, 0), clusterLockFile),
				DKGConfig:         dkg.Config{NoVerify: true},
				ParticipatingENRs: test.enrs,
			})
			require.ErrorContains(t, err, test.errMsg)
			require.Empty(t, buf.String())
		})
	}
}

func TestProposerEditProposalFile(t *testing.T) {
	const proposalJSON = `{"version":"v1.0.0","lock_hash":"0x0102","revision":3,` +
		`"default_config":{"fee_recipient":"` + editFeeRecipientLower + `","gas_limit":"60000000"}}`

	dir := t.TempDir()
	file := path.Join(dir, "proposal.json")
	require.NoError(t, os.WriteFile(file, []byte(proposalJSON), 0o600))

	invalid := path.Join(dir, "invalid.json")
	require.NoError(t, os.WriteFile(invalid, []byte(`{"version":"v1.0.0","revision":3,"default_config":{"gas_limit":"1"}}`), 0o600))

	run := func(t *testing.T, args ...string) (dkg.ProposerConfigEditConfig, error) {
		t.Helper()

		var got dkg.ProposerConfigEditConfig

		cmd := newProposerEditCmd(func(_ context.Context, _ io.Writer, conf dkg.ProposerConfigEditConfig) error {
			got = conf
			return nil
		})
		cmd.SetArgs(append(args, "--yes"))
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)

		return got, cmd.Execute()
	}

	t.Run("proposal file", func(t *testing.T) {
		got, err := run(t, file)
		require.NoError(t, err)
		require.Equal(t, proposerconfig.Delta{}, got.Delta)
		require.NotNil(t, got.Proposal)
		require.Equal(t, uint64(3), got.Proposal.Revision)
		require.Equal(t, []byte{1, 2}, got.Proposal.LockHash)
		require.Equal(t, "60000000", got.Proposal.Config.DefaultConfig.GasLimit)
	})

	t.Run("proposal file from url", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(proposalJSON))
		}))
		defer srv.Close()

		got, err := run(t, srv.URL+"/proposal.json")
		require.NoError(t, err)
		require.NotNil(t, got.Proposal)
		require.Equal(t, uint64(3), got.Proposal.Revision)
		require.Equal(t, "60000000", got.Proposal.Config.DefaultConfig.GasLimit)
	})

	tests := []struct {
		name   string
		args   []string
		errMsg string
	}{
		{"file and change flag", []string{file, "--gas-limit=1"}, "a proposal file excludes the change flags"},
		{"file and no builders", []string{file, "--no-builders"}, "a proposal file excludes the change flags"},
		{"two files", []string{file, file}, "accepts at most 1 arg"},
		{"missing file", []string{path.Join(dir, "missing.json")}, "read proposal file"},
		{"invalid file", []string{invalid}, "parse proposal file"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := run(t, test.args...)
			require.ErrorContains(t, err, test.errMsg)
		})
	}
}

func TestProposerEditConfirm(t *testing.T) {
	newCmd := func(t *testing.T, terminal bool, in string, got *dkg.ProposerConfigEditConfig) *cobra.Command {
		t.Helper()

		prev := isInteractive
		isInteractive = func() bool { return terminal }

		t.Cleanup(func() { isInteractive = prev })

		cmd := newProposerEditCmd(func(_ context.Context, _ io.Writer, conf dkg.ProposerConfigEditConfig) error {
			*got = conf
			return nil
		})
		cmd.SetArgs([]string{"--gas-limit=60000000"})
		cmd.SetIn(strings.NewReader(in))
		cmd.SetErr(io.Discard)

		return cmd
	}

	t.Run("no terminal without yes", func(t *testing.T) {
		var got dkg.ProposerConfigEditConfig

		cmd := newCmd(t, false, "", &got)
		cmd.SetOut(io.Discard)
		require.ErrorContains(t, cmd.Execute(), "add --yes")
	})

	change := dkg.ProposerConfigChange{BaseRevision: 1, Revision: 2, Hash: [32]byte{0xab}, Diff: []string{"gas_limit: 36000000 -> 60000000"}}

	for _, test := range []struct {
		answer string
		errMsg string
	}{
		{"y\n", ""},
		{"YES\n", ""},
		{"n\n", "change not confirmed"},
		{"", "change not confirmed"},
	} {
		t.Run("answer "+strings.TrimSpace(test.answer), func(t *testing.T) {
			var (
				got dkg.ProposerConfigEditConfig
				out bytes.Buffer
			)

			cmd := newCmd(t, true, test.answer, &got)
			cmd.SetOut(&out)
			require.NoError(t, cmd.Execute())
			require.NotNil(t, got.Confirm)

			err := got.Confirm(t.Context(), change)
			if test.errMsg != "" {
				require.ErrorContains(t, err, test.errMsg)
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, "Proposer config revision 2 (hash 0xab00000000000000…), changes from revision 1:\n"+
				"  gas_limit: 36000000 -> 60000000\n"+
				"Sign this change? [y/N] ", out.String())
		})
	}
}

func TestConfirmChangeCancelled(t *testing.T) {
	in, _ := io.Pipe() // Never answers.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	err := confirmChange(in, io.Discard)(ctx, dkg.ProposerConfigChange{})
	require.ErrorIs(t, err, context.Canceled)
}

func TestProposerEditHiddenFlags(t *testing.T) {
	cmd := newProposerEditCmd(nil)

	for _, name := range []string{"overrides-file", "timeout", "shutdown-delay", "no-verify", "execution-client-rpc-endpoint"} {
		require.True(t, cmd.Flags().Lookup(name).Hidden, name)
	}

	for _, name := range []string{"yes", "lock-file", "private-key-file", "proposer-config-file", "participating-operator-enrs", "p2p-relays", gasLimitFlag} {
		require.False(t, cmd.Flags().Lookup(name).Hidden, name)
	}

	// Change flags have no default, a flag left out changes nothing.
	for _, name := range proposerChangeFlagNames {
		require.Contains(t, []string{"", "0", "false", "[]"}, cmd.Flags().Lookup(name).DefValue, name)
	}
}

func TestProposerEditOutput(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var buf bytes.Buffer

		printProposerEditResult(&buf, dkg.ProposerConfigEditResult{
			Revision:  4,
			Hash:      [32]byte{0x7c, 0x41, 0xff},
			Signers:   4,
			Operators: 4,
		})

		require.Equal(t, "Proposer config updated to revision 4 (hash 0x7c41ff0000000000…) with 4/4 operator signatures.\n"+
			"Restart your validator client now to apply it, e.g.: docker compose restart <vc service>\n", buf.String())
	})

	t.Run("adopted", func(t *testing.T) {
		var buf bytes.Buffer

		printProposerEditResult(&buf, dkg.ProposerConfigEditResult{Revision: 2, Signers: 3, Operators: 4, Adopted: true})

		require.Contains(t, buf.String(), "adopted a newer signed revision from its peers")
		require.Contains(t, buf.String(), "revision 2 (hash 0x0000000000000000…) with 3/4 operator signatures.")
	})

	t.Run("pre-gloas warning", func(t *testing.T) {
		var buf bytes.Buffer

		printPreGloasWarning(&buf, cluster.Lock{ForkVersion: []byte{0x10, 0x00, 0x09, 0x10}}, time.Now())

		require.Contains(t, buf.String(), "builder registrations are unaffected")
		require.Contains(t, buf.String(), "feerecipient sign and fetch")
	})

	t.Run("no warning on an unknown network", func(t *testing.T) {
		var buf bytes.Buffer

		printPreGloasWarning(&buf, cluster.Lock{ForkVersion: []byte{0xde, 0xad, 0xbe, 0xef}}, time.Now())

		require.Empty(t, buf.String())
	})
}

func TestProposerEditIgnoresRunP2PEnv(t *testing.T) {
	// The environment of charon run's container under docker compose exec.
	t.Setenv("CHARON_P2P_TCP_ADDRESS", "0.0.0.0:3610")
	t.Setenv("CHARON_P2P_UDP_ADDRESS", "0.0.0.0:3630")
	t.Setenv("CHARON_P2P_EXTERNAL_HOSTNAME", "node.example.com")
	t.Setenv("CHARON_P2P_EXTERNAL_IP", "203.0.113.1")
	t.Setenv("CHARON_P2P_RELAYS", "https://relay.example.com")

	var got dkg.ProposerConfigEditConfig

	editCmd := newProposerEditCmd(func(_ context.Context, _ io.Writer, conf dkg.ProposerConfigEditConfig) error {
		got = conf
		return nil
	})
	root := newRootCmd(newAlphaCmd(newProposerCmd(nil, editCmd)))
	root.SetArgs([]string{"alpha", "proposer", "edit", "--gas-limit=60000000", "--yes"})
	root.SetOut(io.Discard)
	require.NoError(t, root.Execute())

	require.Empty(t, got.DKGConfig.P2P.TCPAddrs)
	require.Empty(t, got.DKGConfig.P2P.UDPAddrs)
	require.Empty(t, got.DKGConfig.P2P.ExternalHost)
	require.Empty(t, got.DKGConfig.P2P.ExternalIP)
	require.Equal(t, []string{"https://relay.example.com"}, got.DKGConfig.P2P.Relays)

	for _, flag := range []string{"p2p-tcp-address", "p2p-udp-address", "p2p-external-ip", "p2p-external-hostname"} {
		require.Nil(t, editCmd.Flags().Lookup(flag), flag)
	}
}
