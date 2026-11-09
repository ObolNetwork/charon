// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bytes"
	"context"
	"io"
	"path"
	"testing"
	"time"

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

func TestEditProposerConfigFlags(t *testing.T) {
	u64 := func(v uint64) *uint64 { return &v }

	tests := []struct {
		name   string
		args   []string
		errMsg string
		patch  proposerconfig.Patch
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
			patch: proposerconfig.Patch{
				FeeRecipient: editFeeRecipientSum,
			},
		},
		{
			name: "validator scoped",
			args: []string{"--fee-recipient=" + editFeeRecipientSum, "--fee-recipient-validators=0xabc,0xdef"},
			patch: proposerconfig.Patch{
				FeeRecipient:           editFeeRecipientSum,
				FeeRecipientValidators: []string{"0xabc", "0xdef"},
			},
		},
		{
			name: "gas limit only leaves builder fields unset",
			args: []string{"--gas-limit=60000000"},
			patch: proposerconfig.Patch{
				GasLimit: 60000000,
			},
		},
		{
			name: "combined",
			args: []string{
				"--fee-recipient=" + editFeeRecipientSum, "--gas-limit=60000000",
				"--builder-urls=https://a,https://b", "--builder-min-bid=5", "--builder-boost-factor=110", "--builder-max-execution-payment=0",
			},
			patch: proposerconfig.Patch{
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
			patch: proposerconfig.Patch{NoBuilders: true},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var (
				called bool
				got    dkg.ProposerConfigEditConfig
			)

			cmd := newEditProposerConfigCmd(func(_ context.Context, _ io.Writer, conf dkg.ProposerConfigEditConfig) error {
				called = true
				got = conf

				return nil
			})
			cmd.SetArgs(test.args)
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
			require.Equal(t, test.patch, got.Patch)
			require.Equal(t, 24*time.Hour, got.DKGConfig.Timeout)
			require.Equal(t, []string{"https://4.relay.obol.dev"}, got.DKGConfig.P2P.Relays)
			require.Equal(t, ".charon/vc-config/proposer-config.json", got.ProposerConfigFile)
			require.Equal(t, ".charon/builder_registrations_overrides.json", got.OverridesFile)
			require.Zero(t, got.MinOperators)
		})
	}
}

func TestEditProposerConfigMinOperators(t *testing.T) {
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

	for _, minOps := range []int{2, 5} {
		var buf bytes.Buffer

		err := runEditProposerConfig(t.Context(), &buf, dkg.ProposerConfigEditConfig{
			LockFilePath: path.Join(nodeDir(srcDir, 0), clusterLockFile),
			DKGConfig:    dkg.Config{NoVerify: true},
			MinOperators: minOps,
		})
		require.ErrorContains(t, err, "min-operators must be at least the threshold")
		require.Empty(t, buf.String())
	}
}

func TestEditProposerConfigOutput(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var buf bytes.Buffer

		printEditProposerConfigResult(&buf, dkg.ProposerConfigEditResult{
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

		printEditProposerConfigResult(&buf, dkg.ProposerConfigEditResult{Revision: 2, Signers: 3, Operators: 4, Adopted: true})

		require.Contains(t, buf.String(), "adopted a newer signed revision from its peers")
		require.Contains(t, buf.String(), "revision 2 (hash 0x0000000000000000…) with 3/4 operator signatures.")
	})

	t.Run("pre-gloas warning", func(t *testing.T) {
		var buf bytes.Buffer

		printPreGloasWarning(&buf, cluster.Lock{ForkVersion: []byte{0x10, 0x00, 0x09, 0x10}}, time.Now())

		require.Contains(t, buf.String(), "builder registrations are unaffected")
		require.Contains(t, buf.String(), "feerecipient sign and fetch")
	})
}

func TestEditProposerConfigIgnoresRunP2PEnv(t *testing.T) {
	// The environment of charon run's container under docker compose exec.
	t.Setenv("CHARON_P2P_TCP_ADDRESS", "0.0.0.0:3610")
	t.Setenv("CHARON_P2P_UDP_ADDRESS", "0.0.0.0:3630")
	t.Setenv("CHARON_P2P_EXTERNAL_HOSTNAME", "node.example.com")
	t.Setenv("CHARON_P2P_EXTERNAL_IP", "203.0.113.1")
	t.Setenv("CHARON_P2P_RELAYS", "https://relay.example.com")

	var got dkg.ProposerConfigEditConfig

	editCmd := newEditProposerConfigCmd(func(_ context.Context, _ io.Writer, conf dkg.ProposerConfigEditConfig) error {
		got = conf
		return nil
	})
	root := newRootCmd(newAlphaCmd(newEditCmd(editCmd)))
	root.SetArgs([]string{"alpha", "edit", "proposer-config", "--gas-limit=60000000"})
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
