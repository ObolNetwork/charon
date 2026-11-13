// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
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
	// proposalFile is the path or URL of a proposal file, the alternative to the change flags.
	proposalFile string
}

// Names of the change flags of the edit proposer-config command.
const (
	feeRecipientFlag           = "fee-recipient"
	feeRecipientValidatorsFlag = "fee-recipient-validators"
	gasLimitFlag               = "gas-limit"
	builderURLsFlag            = "builder-urls"
	builderMinBidFlag          = "builder-min-bid"
	builderBoostFactorFlag     = "builder-boost-factor"
	builderMaxPaymentFlag      = "builder-max-execution-payment"
	noBuildersFlag             = "no-builders"
)

// editChangeFlags are the change flags of the edit proposer-config command, excluded by a proposal file.
var editChangeFlags = []string{
	feeRecipientFlag, feeRecipientValidatorsFlag, gasLimitFlag, builderURLsFlag, builderMinBidFlag,
	builderBoostFactorFlag, builderMaxPaymentFlag, noBuildersFlag,
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
			"One operator can write the change to a proposal file with --write-proposal-file for the others to pass with --proposal-file in place of the change flags. " +
			"Restart the validator client afterwards to apply it.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := log.InitLogger(config.DKGConfig.Log); err != nil {
				return err
			}

			routeLibP2PLogs() // Route libp2p logging to charon logger

			if cmd.Flags().Changed("write-proposal-file") && config.WriteProposalFile == "" {
				return errors.New("write-proposal-file must not be empty")
			}

			if cmd.Flags().Changed("proposal-file") {
				proposal, err := flags.proposal(cmd, config.WriteProposalFile)
				if err != nil {
					return err
				}

				config.Proposal = &proposal
			} else {
				delta, err := flags.delta(cmd)
				if err != nil {
					return err
				}

				config.Delta = delta
			}

			return runFunc(cmd.Context(), cmd.OutOrStdout(), config)
		},
	}

	f := cmd.Flags()
	f.StringVar(&flags.feeRecipient, feeRecipientFlag, "", "The new default fee recipient address, validators with their own fee recipient keep it. Applied to the validators in --fee-recipient-validators instead if set.")
	f.StringSliceVar(&flags.feeRecipientValidators, feeRecipientValidatorsFlag, nil, "Comma-separated DV public keys the fee recipient applies to in place of the default, a validator set to the default loses its own entry. Requires --fee-recipient and excludes every other change flag.")
	f.Uint64Var(&flags.gasLimit, gasLimitFlag, 0, "The new cluster-wide preferred target gas limit, must be greater than 0.")
	f.StringSliceVar(&flags.builderURLs, builderURLsFlag, nil, "Comma-separated builder API URLs replacing the current ones, in order of preference.")
	f.Uint64Var(&flags.builderMinBid, builderMinBidFlag, 0, "The new minimum builder bid value in gwei. Requires an existing builder block or --builder-urls.")
	f.Uint64Var(&flags.builderBoostFactor, builderBoostFactorFlag, proposerconfig.DefaultBuilderBoostFactor, "The new percentage multiplier applied to builder bid values, must be greater than 0. Requires an existing builder block or --builder-urls.")
	f.Uint64Var(&flags.builderMaxPayment, builderMaxPaymentFlag, 0, "The new maximum execution layer payment in gwei counted when valuing a builder bid. Requires an existing builder block or --builder-urls.")
	f.BoolVar(&flags.noBuilders, noBuildersFlag, false, "Remove the builder settings. Excludes the other --builder-* flags.")
	f.StringVar(&flags.proposalFile, "proposal-file", "", "The path to a proposal file or an HTTP URL, holding the next proposer config revision written by one operator with --write-proposal-file. Excludes the change flags. Must be identical on all operators.")
	f.StringVar(&config.WriteProposalFile, "write-proposal-file", "", "The path to write the proposal file of the change flags to, for the other operators' --proposal-file. Nothing else is changed and no ceremony runs.")
	f.StringSliceVar(&config.ParticipatingENRs, "participating-operator-enrs", nil, "Comma-separated list of operator ENRs participating in the ceremony, this node included. Defaults to all operators, at least the cluster threshold is required.")
	f.StringVar(&config.PrivateKeyPath, "private-key-file", ".charon/charon-enr-private-key", "The path to the charon enr private key file.")
	f.StringVar(&config.LockFilePath, "lock-file", ".charon/cluster-lock.json", "The path to the cluster lock file defining the distributed validator cluster.")
	f.StringVar(&config.ProposerConfigFile, "proposer-config-file", ".charon/vc-config/proposer-config.json", "The path to the proposer config file.")
	f.StringVar(&config.OverridesFile, "overrides-file", ".charon/builder_registrations_overrides.json", "The path to the builder registration overrides file, used for the fee recipients if the proposer config file is absent.")
	f.DurationVar(&config.DKGConfig.Timeout, "timeout", 24*time.Hour, "The time to wait for the other operators to join the ceremony.")
	bindShutdownDelayFlag(f, &config.DKGConfig.ShutdownDelay)

	bindNoVerifyFlag(f, &config.DKGConfig.NoVerify)
	// Relays only: under docker compose exec, charon run's CHARON_P2P_* listen and advertise settings must not apply.
	bindP2PRelaysFlag(cmd, &config.DKGConfig.P2P, defaultDKGRelays...)
	bindLogFlags(f, &config.DKGConfig.Log)
	bindEth1Flag(f, &config.DKGConfig.ExecutionEngineAddr)

	return cmd
}

// proposal returns the unsigned revision of the proposal file, which excludes the change flags and writing one.
func (f editProposerConfigFlags) proposal(cmd *cobra.Command, writeProposalFile string) (proposerconfig.Document, error) {
	if slices.ContainsFunc(editChangeFlags, cmd.Flags().Changed) {
		return proposerconfig.Document{}, errors.New("proposal-file excludes the change flags")
	}

	if writeProposalFile != "" {
		return proposerconfig.Document{}, errors.New("proposal-file excludes write-proposal-file")
	}

	b, err := readFileOrURL(cmd.Context(), f.proposalFile)
	if err != nil {
		return proposerconfig.Document{}, errors.Wrap(err, "read proposal file")
	}

	doc, err := proposerconfig.ParseProposal(b)
	if err != nil {
		return proposerconfig.Document{}, errors.Wrap(err, "parse proposal file")
	}

	log.Info(cmd.Context(), "Proposal file loaded", z.Str("source", log.RedactURL(f.proposalFile, false)), z.U64("revision", doc.Revision))

	return doc, nil
}

// delta validates the change flags and returns the delta they describe.
func (f editProposerConfigFlags) delta(cmd *cobra.Command) (proposerconfig.Delta, error) {
	changed := cmd.Flags().Changed
	builderFlags := []string{builderURLsFlag, builderMinBidFlag, builderBoostFactorFlag, builderMaxPaymentFlag}

	var (
		d          proposerconfig.Delta
		anyBuilder bool
	)

	for _, name := range builderFlags {
		anyBuilder = anyBuilder || changed(name)
	}

	switch {
	case changed(feeRecipientValidatorsFlag) && !changed(feeRecipientFlag):
		return d, errors.New("fee-recipient-validators requires fee-recipient")
	case changed(feeRecipientValidatorsFlag) && (changed(gasLimitFlag) || anyBuilder || f.noBuilders):
		return d, errors.New("fee-recipient-validators can only be combined with fee-recipient, gas limit and builders are cluster-wide")
	case f.noBuilders && anyBuilder:
		return d, errors.New("no-builders excludes the other builder-* flags")
	case !changed(feeRecipientFlag) && !changed(gasLimitFlag) && !anyBuilder && !f.noBuilders:
		return d, errors.New("no change requested, set at least one of fee-recipient, gas-limit, builder-* or no-builders")
	case changed(gasLimitFlag) && f.gasLimit == 0:
		return d, errors.New("gas-limit must be greater than 0")
	case changed(builderBoostFactorFlag) && f.builderBoostFactor == 0:
		return d, errors.New("builder-boost-factor must be greater than 0")
	case changed(builderURLsFlag) && len(f.builderURLs) == 0:
		return d, errors.New("builder-urls must not be empty, use no-builders to remove the builders")
	}

	if changed(feeRecipientFlag) {
		addr, err := eth2util.ValidateChecksumAddress(f.feeRecipient)
		if err != nil {
			return d, errors.Wrap(err, "invalid fee-recipient address", z.Str("addr", f.feeRecipient))
		}

		if addr == zeroAddress {
			return d, errors.New("zero fee-recipient address forbidden")
		}

		d.FeeRecipient = addr
		d.FeeRecipientValidators = f.feeRecipientValidators
	}

	d.GasLimit = f.gasLimit
	d.NoBuilders = f.noBuilders

	if changed(builderURLsFlag) {
		d.BuilderURLs = f.builderURLs
	}

	if changed(builderMinBidFlag) {
		d.BuilderMinBid = &f.builderMinBid
	}

	if changed(builderBoostFactorFlag) {
		d.BuilderBoostFactor = &f.builderBoostFactor
	}

	if changed(builderMaxPaymentFlag) {
		d.BuilderMaxExecutionPayment = &f.builderMaxPayment
	}

	return d, nil
}

func runEditProposerConfig(ctx context.Context, w io.Writer, conf dkg.ProposerConfigEditConfig) error {
	lock, err := dkg.LoadAndVerifyClusterLock(ctx, conf.LockFilePath, conf.DKGConfig.ExecutionEngineAddr, conf.DKGConfig.NoVerify)
	if err != nil {
		return errors.Wrap(err, "load cluster lock")
	}

	if err := validateEditParticipants(conf.ParticipatingENRs, *lock); err != nil {
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

// validateEditParticipants checks the participating operator ENRs, none meaning all, against the lock.
func validateEditParticipants(enrs []string, lock cluster.Lock) error {
	if len(enrs) == 0 {
		return nil
	}

	if hasDuplicateENRs(enrs) {
		return errors.New("participating-operator-enrs contains duplicate ENRs")
	}

	for _, enr := range enrs {
		if !slices.ContainsFunc(lock.Operators, func(o cluster.Operator) bool { return o.ENR == enr }) {
			return errors.New("participating-operator-enrs contains a non-existing operator")
		}
	}

	if len(enrs) < lock.Threshold {
		return errors.New("participating-operator-enrs must list at least the threshold of operators",
			z.Int("participating", len(enrs)), z.Int("threshold", lock.Threshold))
	}

	return nil
}

// printPreGloasWarning warns that charon's builder registrations are unaffected before the gloas fork,
// on the known networks whose fork time is known.
func printPreGloasWarning(w io.Writer, lock cluster.Lock, now time.Time) {
	_, err := eth2util.ForkVersionToNetwork(lock.ForkVersion)
	if err != nil || eth2util.GloasActive(lock.ForkVersion, now) {
		return
	}

	_, _ = fmt.Fprintln(w, "Warning: the gloas fork is not active yet, charon's own builder registrations are unaffected by the proposer config until then. "+
		"A fee recipient change before the fork also needs charon feerecipient sign and fetch.")
}

// printEditProposerConfigResult prints the outcome and the VC restart instruction.
func printEditProposerConfigResult(w io.Writer, res dkg.ProposerConfigEditResult) {
	if res.ProposalFile != "" {
		_, _ = fmt.Fprintf(w, "Proposal for proposer config revision %d (hash 0x%s…) written to %s.\n",
			res.Revision, hex.EncodeToString(res.Hash[:8]), res.ProposalFile)
		_, _ = fmt.Fprintln(w, "Nothing is changed yet: send the file to the other operators, then all run this command with --proposal-file.")

		return
	}

	if res.Adopted {
		_, _ = fmt.Fprintln(w, "This node was behind and adopted a newer signed revision from its peers as the base of the change.")
	}

	_, _ = fmt.Fprintf(w, "Proposer config updated to revision %d (hash 0x%s…) with %d/%d operator signatures.\n",
		res.Revision, hex.EncodeToString(res.Hash[:8]), res.Signers, res.Operators)
	_, _ = fmt.Fprintln(w, "Restart your validator client now to apply it, e.g.: docker compose restart <vc service>")
}
