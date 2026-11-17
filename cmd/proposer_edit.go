// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/term"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
	"github.com/obolnetwork/charon/dkg"
	"github.com/obolnetwork/charon/eth2util"
)

// proposerChangeFlags holds the change flags of the proposer create and edit commands.
type proposerChangeFlags struct {
	feeRecipient           string
	feeRecipientValidators []string
	gasLimit               uint64
	builderURLs            []string
	builderMinBid          uint64
	builderBoostFactor     uint64
	builderMaxPayment      uint64
	noBuilders             bool
}

// Names of the change flags of the proposer create and edit commands.
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

// proposerChangeFlagNames are the change flags, excluded by a proposal file.
var proposerChangeFlagNames = []string{
	feeRecipientFlag, feeRecipientValidatorsFlag, gasLimitFlag, builderURLsFlag, builderMinBidFlag,
	builderBoostFactorFlag, builderMaxPaymentFlag, noBuildersFlag,
}

// stdinIsTerminal reports whether stdin is a terminal, the confirmation question needs one.
var stdinIsTerminal = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

// bind binds the change flags. None has a default: a flag left out changes nothing.
func (f *proposerChangeFlags) bind(fs *pflag.FlagSet) {
	fs.StringVar(&f.feeRecipient, feeRecipientFlag, "", "The new default fee recipient address, validators with their own fee recipient keep it. Applied to the validators in --fee-recipient-validators instead if set.")
	fs.StringSliceVar(&f.feeRecipientValidators, feeRecipientValidatorsFlag, nil, "Comma-separated DV public keys the fee recipient applies to, the default is left as is. A validator set to the default loses its own entry. Requires --fee-recipient and excludes every other change flag.")
	fs.Uint64Var(&f.gasLimit, gasLimitFlag, 0, "The new cluster-wide preferred target gas limit, must be greater than 0.")
	fs.StringSliceVar(&f.builderURLs, builderURLsFlag, nil, "Comma-separated builder API URLs replacing the current ones, in order of preference.")
	fs.Uint64Var(&f.builderMinBid, builderMinBidFlag, 0, "The new minimum builder bid value in gwei. Requires an existing builder block or --builder-urls.")
	fs.Uint64Var(&f.builderBoostFactor, builderBoostFactorFlag, 0, "The new percentage multiplier applied to builder bid values, must be greater than 0. Requires an existing builder block or --builder-urls.")
	fs.Uint64Var(&f.builderMaxPayment, builderMaxPaymentFlag, 0, "The new maximum execution layer payment in gwei counted when valuing a builder bid. Requires an existing builder block or --builder-urls.")
	fs.BoolVar(&f.noBuilders, noBuildersFlag, false, "Remove the builder settings. Excludes the other --builder-* flags.")
}

// markHidden hides the plumbing flags from the help text, they keep working.
func markHidden(fs *pflag.FlagSet, names ...string) {
	for _, name := range names {
		if err := fs.MarkHidden(name); err != nil {
			panic(err) // Only fails on an unknown flag name, a programming error.
		}
	}
}

func newProposerEditCmd(runFunc func(context.Context, io.Writer, dkg.ProposerConfigEditConfig) error) *cobra.Command {
	var (
		config dkg.ProposerConfigEditConfig
		flags  proposerChangeFlags
		yes    bool
	)

	cmd := &cobra.Command{
		Use:   "edit [proposal file or URL]",
		Short: "Change the cluster's signed proposer config with the other operators",
		Long: "Changes the fee recipients, gas limit or builders in the cluster's proposer config file. " +
			"All participating operators run this command with the same change: the change flags, or a proposal file written with charon alpha proposer create (a path or an HTTP URL). " +
			"Each operator confirms the change before signing it, then all agree on the new revision and each writes it with the collected signatures. " +
			"Restart the validator client afterwards to apply it.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := log.InitLogger(config.DKGConfig.Log); err != nil {
				return err
			}

			routeLibP2PLogs() // Route libp2p logging to charon logger

			if len(args) == 1 {
				if slices.ContainsFunc(proposerChangeFlagNames, cmd.Flags().Changed) {
					return errors.New("a proposal file excludes the change flags")
				}

				proposal, err := loadProposal(cmd.Context(), args[0])
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

			if !yes {
				if !stdinIsTerminal() {
					return errors.New("confirming the change needs a terminal, add --yes to sign it without asking")
				}

				config.Confirm = confirmChange(cmd.InOrStdin(), cmd.OutOrStdout())
			}

			return runFunc(cmd.Context(), cmd.OutOrStdout(), config)
		},
	}

	f := cmd.Flags()
	flags.bind(f)
	f.BoolVar(&yes, "yes", false, "Sign the change without asking to confirm it, for scripts.")
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

	markHidden(f, "overrides-file", "timeout", "shutdown-delay", "no-verify", "p2p-relays", "execution-client-rpc-endpoint")

	return cmd
}

// loadProposal returns the unsigned revision of the proposal file at the path or URL.
func loadProposal(ctx context.Context, source string) (proposerconfig.Document, error) {
	b, err := readFileOrURL(ctx, source)
	if err != nil {
		return proposerconfig.Document{}, errors.Wrap(err, "read proposal file")
	}

	doc, err := proposerconfig.ParseProposal(b)
	if err != nil {
		return proposerconfig.Document{}, errors.Wrap(err, "parse proposal file")
	}

	log.Info(ctx, "Proposal file loaded", z.Str("source", log.RedactURL(source, false)), z.U64("revision", doc.Revision))

	return doc, nil
}

// confirmChange returns a Confirm function printing the change to w and asking on in to sign it: any answer but
// y or yes declines.
func confirmChange(in io.Reader, w io.Writer) func(context.Context, dkg.ProposerConfigChange) error {
	return func(_ context.Context, change dkg.ProposerConfigChange) error {
		printProposerConfigChange(w, change)

		_, _ = fmt.Fprint(w, "Sign this change? [y/N] ")

		answer, err := bufio.NewReader(in).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return errors.Wrap(err, "read confirmation")
		}

		switch strings.ToLower(strings.TrimSpace(answer)) {
		case "y", "yes":
			return nil
		default:
			return errors.New("change not confirmed, nothing was signed")
		}
	}
}

// printProposerConfigChange prints the proposed revision and its changes.
func printProposerConfigChange(w io.Writer, change dkg.ProposerConfigChange) {
	_, _ = fmt.Fprintf(w, "Proposer config revision %d (hash 0x%s…), changes from revision %d:\n",
		change.Revision, hex.EncodeToString(change.Hash[:8]), change.BaseRevision)

	for _, line := range change.Diff {
		_, _ = fmt.Fprintln(w, "  "+line)
	}
}

// delta validates the change flags and returns the delta they describe.
func (f proposerChangeFlags) delta(cmd *cobra.Command) (proposerconfig.Delta, error) {
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

func runProposerEdit(ctx context.Context, w io.Writer, conf dkg.ProposerConfigEditConfig) error {
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

	printProposerEditResult(w, res)

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

// printProposerEditResult prints the outcome and the VC restart instruction.
func printProposerEditResult(w io.Writer, res dkg.ProposerConfigEditResult) {
	if res.Adopted {
		_, _ = fmt.Fprintln(w, "This node was behind and adopted a newer signed revision from its peers as the base of the change.")
	}

	_, _ = fmt.Fprintf(w, "Proposer config updated to revision %d (hash 0x%s…) with %d/%d operator signatures.\n",
		res.Revision, hex.EncodeToString(res.Hash[:8]), res.Signers, res.Operators)
	_, _ = fmt.Fprintln(w, "Restart your validator client now to apply it, e.g.: docker compose restart <vc service>")
}
