// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
	"github.com/obolnetwork/charon/dkg"
	"github.com/obolnetwork/charon/eth2util"
)

// editProposerConfigFlags holds the change flags of the edit proposer-config command.
type editProposerConfigFlags struct {
	feeRecipient           string
	feeRecipientValidators []string
	gasLimit               uint64
	builderURLs            []string
	builderMinBid          uint64
	builderBoostFactor     uint64
	builderMaxPayment      uint64
	noBuilders             bool
}

func newEditProposerConfigCmd(runFunc func(context.Context, io.Writer, dkg.ProposerConfigEditConfig) error) *cobra.Command {
	var (
		config dkg.ProposerConfigEditConfig
		flags  editProposerConfigFlags
	)

	cmd := &cobra.Command{
		Use:   "proposer-config",
		Short: "Change the cluster's signed proposer config",
		Long: "Changes the fee recipients, gas limit or builders in the cluster's proposer config file. " +
			"All participating operators run the same command, agree on the new revision, sign it and each writes it with the collected signatures. " +
			"Restart the validator client afterwards to apply it.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			patch, err := flags.patch(cmd)
			if err != nil {
				return err
			}

			config.Patch = patch

			if err := log.InitLogger(config.DKGConfig.Log); err != nil {
				return err
			}

			routeLibP2PLogs() // Route libp2p logging to charon logger

			return runFunc(cmd.Context(), cmd.OutOrStdout(), config)
		},
	}

	f := cmd.Flags()
	f.StringVar(&flags.feeRecipient, "fee-recipient", "", "The new fee recipient address, applied to all validators or those in --fee-recipient-validators.")
	f.StringSliceVar(&flags.feeRecipientValidators, "fee-recipient-validators", nil, "Comma-separated DV public keys the fee recipient applies to, default all. Requires --fee-recipient and excludes every other change flag.")
	f.Uint64Var(&flags.gasLimit, "gas-limit", 0, "The new cluster-wide preferred target gas limit, must be greater than 0.")
	f.StringSliceVar(&flags.builderURLs, "builder-urls", nil, "Comma-separated builder API URLs replacing the current ones, in order of preference.")
	f.Uint64Var(&flags.builderMinBid, "builder-min-bid", 0, "The new minimum builder bid value in gwei. Requires an existing builder block or --builder-urls.")
	f.Uint64Var(&flags.builderBoostFactor, "builder-boost-factor", proposerconfig.DefaultBuilderBoostFactor, "The new percentage multiplier applied to builder bid values, must be greater than 0. Requires an existing builder block or --builder-urls.")
	f.Uint64Var(&flags.builderMaxPayment, "builder-max-execution-payment", 0, "The new maximum execution layer payment in gwei counted when valuing a builder bid. Requires an existing builder block or --builder-urls.")
	f.BoolVar(&flags.noBuilders, "no-builders", false, "Remove the builder settings. Excludes the other --builder-* flags.")
	f.IntVar(&config.MinOperators, "min-operators", 0, "The number of operators, this one included, to proceed with. Defaults to all operators, must be at least the cluster threshold.")
	f.StringVar(&config.PrivateKeyPath, "private-key-file", ".charon/charon-enr-private-key", "The path to the charon enr private key file.")
	f.StringVar(&config.LockFilePath, "lock-file", ".charon/cluster-lock.json", "The path to the cluster lock file defining the distributed validator cluster.")
	f.StringVar(&config.ProposerConfigFile, "proposer-config-file", ".charon/vc-config/proposer-config.json", "The path to the proposer config file.")
	f.StringVar(&config.OverridesFile, "overrides-file", ".charon/builder_registrations_overrides.json", "The path to the builder registration overrides file, used for the fee recipients if the proposer config file is absent.")
	f.DurationVar(&config.DKGConfig.Timeout, "timeout", 24*time.Hour, "The time to wait for the other operators to join the ceremony.")

	bindNoVerifyFlag(f, &config.DKGConfig.NoVerify)
	// Relays only: under docker compose exec, charon run's CHARON_P2P_* listen and advertise settings must not apply.
	bindP2PRelaysFlag(cmd, &config.DKGConfig.P2P, defaultDKGRelays...)
	bindLogFlags(f, &config.DKGConfig.Log)
	bindEth1Flag(f, &config.DKGConfig.ExecutionEngineAddr)

	return cmd
}

// patch validates the change flags and returns the patch they describe.
func (f editProposerConfigFlags) patch(cmd *cobra.Command) (proposerconfig.Patch, error) {
	changed := cmd.Flags().Changed
	builderFlags := []string{"builder-urls", "builder-min-bid", "builder-boost-factor", "builder-max-execution-payment"}

	var (
		p          proposerconfig.Patch
		anyBuilder bool
	)

	for _, name := range builderFlags {
		anyBuilder = anyBuilder || changed(name)
	}

	switch {
	case changed("fee-recipient-validators") && !changed("fee-recipient"):
		return p, errors.New("fee-recipient-validators requires fee-recipient")
	case changed("fee-recipient-validators") && (changed("gas-limit") || anyBuilder || f.noBuilders):
		return p, errors.New("fee-recipient-validators can only be combined with fee-recipient, gas limit and builders are cluster-wide")
	case f.noBuilders && anyBuilder:
		return p, errors.New("no-builders excludes the other builder-* flags")
	case !changed("fee-recipient") && !changed("gas-limit") && !anyBuilder && !f.noBuilders:
		return p, errors.New("no change requested, set at least one of fee-recipient, gas-limit, builder-* or no-builders")
	case changed("gas-limit") && f.gasLimit == 0:
		return p, errors.New("gas-limit must be greater than 0")
	case changed("builder-boost-factor") && f.builderBoostFactor == 0:
		return p, errors.New("builder-boost-factor must be greater than 0")
	case changed("builder-urls") && len(f.builderURLs) == 0:
		return p, errors.New("builder-urls must not be empty, use no-builders to remove the builders")
	}

	if changed("fee-recipient") {
		addr, err := eth2util.ValidateChecksumAddress(f.feeRecipient)
		if err != nil {
			return p, errors.Wrap(err, "invalid fee-recipient address", z.Str("addr", f.feeRecipient))
		}

		if addr == zeroAddress {
			return p, errors.New("zero fee-recipient address forbidden")
		}

		p.FeeRecipient = addr
		p.FeeRecipientValidators = f.feeRecipientValidators
	}

	p.GasLimit = f.gasLimit
	p.NoBuilders = f.noBuilders

	if changed("builder-urls") {
		p.BuilderURLs = f.builderURLs
	}

	if changed("builder-min-bid") {
		p.BuilderMinBid = &f.builderMinBid
	}

	if changed("builder-boost-factor") {
		p.BuilderBoostFactor = &f.builderBoostFactor
	}

	if changed("builder-max-execution-payment") {
		p.BuilderMaxExecutionPayment = &f.builderMaxPayment
	}

	return p, nil
}

func runEditProposerConfig(ctx context.Context, w io.Writer, conf dkg.ProposerConfigEditConfig) error {
	lock, err := dkg.LoadAndVerifyClusterLock(ctx, conf.LockFilePath, conf.DKGConfig.ExecutionEngineAddr, conf.DKGConfig.NoVerify)
	if err != nil {
		return errors.Wrap(err, "load cluster lock")
	}

	if err := validateEditMinOperators(conf.MinOperators, *lock); err != nil {
		return err
	}

	printPreGloasWarning(w, *lock, time.Now())

	res, err := dkg.RunProposerConfigEdit(ctx, conf)
	if err != nil {
		return errors.Wrap(err, "run proposer config edit")
	}

	printEditProposerConfigResult(w, res)

	return nil
}

// validateEditMinOperators checks min operators, 0 meaning all, against the lock.
func validateEditMinOperators(minOperators int, lock cluster.Lock) error {
	if minOperators != 0 && (minOperators < lock.Threshold || minOperators > len(lock.Operators)) {
		return errors.New("min-operators must be at least the threshold and at most the number of operators",
			z.Int("min_operators", minOperators), z.Int("threshold", lock.Threshold), z.Int("operators", len(lock.Operators)))
	}

	return nil
}

// printPreGloasWarning warns that charon's builder registrations are unaffected before the gloas fork.
func printPreGloasWarning(w io.Writer, lock cluster.Lock, now time.Time) {
	if eth2util.GloasActive(lock.ForkVersion, now) {
		return
	}

	_, _ = fmt.Fprintln(w, "Warning: the gloas fork is not active yet, charon's own builder registrations are unaffected by the proposer config until then. "+
		"A fee recipient change before the fork also needs charon feerecipient sign and fetch.")
}

// printEditProposerConfigResult prints the outcome and the VC restart instruction.
func printEditProposerConfigResult(w io.Writer, res dkg.ProposerConfigEditResult) {
	if res.Adopted {
		_, _ = fmt.Fprintln(w, "This node was behind and adopted a newer signed revision from its peers as the base of the change.")
	}

	_, _ = fmt.Fprintf(w, "Proposer config updated to revision %d (hash 0x%s…) with %d/%d operator signatures.\n",
		res.Revision, hex.EncodeToString(res.Hash[:8]), res.Signers, res.Operators)
	_, _ = fmt.Fprintln(w, "Restart your validator client now to apply it, e.g.: docker compose restart <vc service>")
}
