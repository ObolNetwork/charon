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
	validatorPublicKeys   []string
	feeRecipientAddresses []string
	allValidators         bool
	gasLimit              uint64
	builderURLs           []string
	builderMinBid         uint64
	builderBoostFactor    uint64
	builderMaxPayment     uint64
	noBuilders            bool
}

// Names of the change flags of the proposer create and edit commands.
const (
	validatorPublicKeysFlag   = "validator-public-keys"
	feeRecipientAddressesFlag = "fee-recipient-addresses"
	allValidatorsFlag         = "all"
	gasLimitFlag              = "gas-limit"
	builderURLsFlag           = "builder-urls"
	builderMinBidFlag         = "builder-min-bid"
	builderBoostFactorFlag    = "builder-boost-factor"
	builderMaxPaymentFlag     = "builder-max-execution-payment"
	noBuildersFlag            = "no-builders"
)

// proposerChangeFlagNames are the change flags, excluded by a proposal file.
var proposerChangeFlagNames = []string{
	validatorPublicKeysFlag, feeRecipientAddressesFlag, allValidatorsFlag, gasLimitFlag, builderURLsFlag,
	builderMinBidFlag, builderBoostFactorFlag, builderMaxPaymentFlag, noBuildersFlag,
}

// isInteractive reports whether stdin and stdout are terminals, the confirmation question needs both.
var isInteractive = func() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

// bind binds the change flags. None has a default: a flag left out changes nothing.
func (f *proposerChangeFlags) bind(fs *pflag.FlagSet) {
	fs.StringSliceVar(&f.validatorPublicKeys, validatorPublicKeysFlag, nil, "Comma-separated DV public keys whose fee recipient changes. Requires --fee-recipient-addresses with one address per public key, in the same order.")
	fs.StringSliceVar(&f.feeRecipientAddresses, feeRecipientAddressesFlag, nil, "Comma-separated new fee recipient addresses, one per public key in --validator-public-keys, or a single address with --all.")
	fs.BoolVar(&f.allValidators, allValidatorsFlag, false, "Change the fee recipient of every validator to the single address in --fee-recipient-addresses. Excludes --validator-public-keys.")
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
		Short: "Change the cluster's proposer config in a ceremony all operators run at the same time",
		Long: "Changes the fee recipients, gas limit or builders in the cluster's proposer config file. " +
			"It is a ceremony, like a DKG: one operator running it alone changes nothing. Agree on a time with the other operators, then all participating operators run this command " +
			"at the same time and with the same change: a proposal file written with charon alpha proposer create (a path or an HTTP URL), or the equal change flags. " +
			"The command waits for the others to join. Each operator confirms the change before signing it, then all agree on the new revision and each writes it with the collected signatures. " +
			"Afterwards rerun charon alpha vc-bundle and restart the validator client to apply it: a restart alone keeps the old settings.",
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
				if !isInteractive() {
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
	f.DurationVar(&config.DKGConfig.Timeout, "timeout", time.Minute, "Timeout for the protocol, should be increased if protocol times out.")
	bindShutdownDelayFlag(f, &config.DKGConfig.ShutdownDelay)

	bindNoVerifyFlag(f, &config.DKGConfig.NoVerify)
	// Relays only: under docker compose exec, charon run's CHARON_P2P_* listen and advertise settings must not apply.
	bindP2PRelaysFlag(cmd, &config.DKGConfig.P2P, defaultDKGRelays...)
	bindLogFlags(f, &config.DKGConfig.Log)
	bindEth1Flag(f, &config.DKGConfig.ExecutionEngineAddr)

	// p2p-relays stays visible: under docker compose exec it must be passed, see the relay probe.
	markHidden(f, "overrides-file", "timeout", "shutdown-delay", "no-verify", "execution-client-rpc-endpoint")

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
// y or yes declines. A cancelled context, as on an interrupt or the ceremony's timeout, ends the wait.
func confirmChange(in io.Reader, w io.Writer) func(context.Context, dkg.ProposerConfigChange) error {
	// One reader for all questions, so input buffered by one is not lost to the next.
	reader := bufio.NewReader(in)

	type answer struct {
		line string
		err  error
	}

	return func(ctx context.Context, change dkg.ProposerConfigChange) error {
		printProposerConfigChange(w, change)

		_, _ = fmt.Fprint(w, "Sign this change? [y/N] ")

		answers := make(chan answer, 1)

		go func() {
			line, err := reader.ReadString('\n')
			answers <- answer{line: line, err: err}
		}()

		select {
		case <-ctx.Done():
			return errors.Wrap(ctx.Err(), "change not confirmed, nothing was signed")
		case a := <-answers:
			if a.err != nil && !errors.Is(a.err, io.EOF) {
				return errors.Wrap(a.err, "read confirmation")
			}

			switch strings.ToLower(strings.TrimSpace(a.line)) {
			case "y", "yes":
				return nil
			default:
				return errors.New("change not confirmed, nothing was signed")
			}
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

	anyFeeRecipient := changed(validatorPublicKeysFlag) || changed(feeRecipientAddressesFlag) || f.allValidators

	switch {
	case f.noBuilders && anyBuilder:
		return d, errors.New("no-builders excludes the other builder-* flags")
	case !anyFeeRecipient && !changed(gasLimitFlag) && !anyBuilder && !f.noBuilders:
		return d, errors.New("no change requested, set at least one of fee-recipient-addresses, gas-limit, builder-* or no-builders")
	case changed(gasLimitFlag) && f.gasLimit == 0:
		return d, errors.New("gas-limit must be greater than 0")
	case changed(builderBoostFactorFlag) && f.builderBoostFactor == 0:
		return d, errors.New("builder-boost-factor must be greater than 0")
	case changed(builderURLsFlag) && len(f.builderURLs) == 0:
		return d, errors.New("builder-urls must not be empty, use no-builders to remove the builders")
	}

	if anyFeeRecipient {
		err := f.validateFeeRecipients()
		if err != nil {
			return d, err
		}

		d.FeeRecipientValidators = f.validatorPublicKeys
		d.AllValidators = f.allValidators

		for _, addr := range f.feeRecipientAddresses {
			checksummed, err := eth2util.ValidateChecksumAddress(addr)
			if err != nil {
				return d, errors.Wrap(err, "invalid fee-recipient-addresses address", z.Str("addr", addr))
			}

			if checksummed == zeroAddress {
				return d, errors.New("zero fee-recipient-addresses address forbidden")
			}

			d.FeeRecipients = append(d.FeeRecipients, checksummed)
		}
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

// validateFeeRecipients checks that the fee recipient flags are strictly paired: one address per validator
// public key, or a single address for all validators.
func (f proposerChangeFlags) validateFeeRecipients() error {
	keys, addrs := len(f.validatorPublicKeys), len(f.feeRecipientAddresses)

	switch {
	case f.allValidators && keys > 0:
		return errors.New("all excludes validator-public-keys")
	case f.allValidators && addrs != 1:
		return errors.New("all requires a single address in fee-recipient-addresses", z.Int("fee_recipient_addresses", addrs))
	case f.allValidators:
		return nil
	case keys == 0:
		return errors.New("no validators given, add all to change every validator's fee recipient or list them with validator-public-keys")
	case keys != addrs:
		return errors.New("validator-public-keys and fee-recipient-addresses must be the same length, one address per validator, use all to give every validator the same address",
			z.Int("validator_public_keys", keys), z.Int("fee_recipient_addresses", addrs))
	}

	return nil
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

	_, err = dkg.RunProposerConfigEdit(ctx, conf)
	if err != nil {
		return errors.Wrap(err, "run proposer config edit")
	}

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
