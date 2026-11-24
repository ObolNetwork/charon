// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
	"github.com/obolnetwork/charon/dkg"
)

// proposerViewConfig is the configuration of the read-only proposer commands: the status and list.
type proposerViewConfig struct {
	LockFile           string
	ProposerConfigFile string
	NoVerify           bool
}

func newProposerCmd(runStatus func(context.Context, io.Writer, proposerViewConfig) error, cmds ...*cobra.Command) *cobra.Command {
	var config proposerViewConfig

	cmd := &cobra.Command{
		Use:   "proposer",
		Short: "Show and change the cluster's proposer config: fee recipients, gas limit and builders",
		Long: "Shows the cluster's signed proposer config, the fee recipients, gas limit and builders its validator clients use, and how to change it. " +
			"To change it, all operators run edit at the same time with the same change: either the same change flags, or a proposal file one person wrote with create, which spares everyone retyping the flags.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runStatus(cmd.Context(), cmd.OutOrStdout(), config)
		},
	}

	bindProposerViewFlags(cmd, &config)
	cmd.AddCommand(cmds...)

	return cmd
}

func newProposerListCmd(runFunc func(context.Context, io.Writer, proposerViewConfig) error) *cobra.Command {
	var config proposerViewConfig

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the default proposer config and the validators with their own fee recipient",
		Long: "Lists the default fee recipient and gas limit, the validators whose fee recipient differs from the default, and the builders. " +
			"Validators on the default are counted, not listed. Builder URL credentials are hidden.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFunc(cmd.Context(), cmd.OutOrStdout(), config)
		},
	}

	bindProposerViewFlags(cmd, &config)

	return cmd
}

func bindProposerViewFlags(cmd *cobra.Command, config *proposerViewConfig) {
	cmd.Flags().StringVar(&config.LockFile, "lock-file", ".charon/cluster-lock.json", "The path to the cluster lock file defining the distributed validator cluster.")
	cmd.Flags().StringVar(&config.ProposerConfigFile, "proposer-config-file", ".charon/vc-config/proposer-config.json", "The path to the proposer config file of any of the cluster's nodes.")
	bindNoVerifyFlag(cmd.Flags(), &config.NoVerify)
	markHidden(cmd.Flags(), "no-verify")
}

// loadProposerView returns the verified lock and its proposer config document, which the caller verifies.
func loadProposerView(ctx context.Context, config proposerViewConfig) (cluster.Lock, proposerconfig.Document, error) {
	lock, err := dkg.LoadAndVerifyClusterLock(ctx, config.LockFile, "", config.NoVerify)
	if err != nil {
		return cluster.Lock{}, proposerconfig.Document{}, errors.Wrap(err, "load cluster lock")
	}

	doc, err := proposerconfig.LoadAnyNode(config.ProposerConfigFile, *lock)
	if err != nil {
		return *lock, proposerconfig.Document{}, err
	}

	return *lock, doc, nil
}

// runProposerStatus prints the cluster's proposer config and how to change it. A missing file is reported, not an error.
func runProposerStatus(ctx context.Context, w io.Writer, config proposerViewConfig) error {
	lock, doc, err := loadProposerView(ctx, config)
	if len(lock.Operators) > 0 {
		_, _ = fmt.Fprintf(w, "Cluster %q, lock 0x%s…, %d operators, threshold %d\n",
			lock.Name, hex.EncodeToString(lock.LockHash[:min(4, len(lock.LockHash))]), len(lock.Operators), lock.Threshold)
	}

	switch {
	case errors.Is(err, proposerconfig.ErrNotFound):
		_, _ = fmt.Fprintf(w, "No proposer config file at %s: charon run writes it from the cluster lock when it starts.\n", config.ProposerConfigFile)
		return nil
	case err != nil:
		return err
	}

	// An unverified document is not shown, its content cannot be trusted.
	err = proposerconfig.Verify(doc, lock)
	if err != nil {
		return errors.Wrap(err, "verify proposer config file")
	}

	hash, err := doc.Hash()
	if err != nil {
		return err
	}

	if doc.Revision == 0 {
		_, _ = fmt.Fprintln(w, "Proposer config revision 0, unsigned: written from the cluster lock, not yet agreed by the operators")
	} else {
		_, _ = fmt.Fprintf(w, "Proposer config revision %s, signed by %d of %d operators: %s\n",
			proposerconfig.RevisionName(doc.Revision, hash), len(doc.Signatures), len(lock.Operators), signerList(doc))
	}

	def := doc.Config.DefaultConfig

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(tw, "  fee recipient\t%s (default), %d validator(s) with their own → charon alpha proposer list\n", def.FeeRecipient, len(doc.Config.ProposerConfig))
	_, _ = fmt.Fprintf(tw, "  gas limit\t%s\n", def.GasLimit)
	_, _ = fmt.Fprintf(tw, "  builders\t%s\n", builderSummary(def.Builder))
	_ = tw.Flush()

	_, _ = fmt.Fprintln(w, "Change it: every operator runs charon alpha proposer edit <change flags> at the same time, or edit <proposal file> with a file from charon alpha proposer create")

	return nil
}

// signerList returns the indexes of the operators that signed the document, as in the lock, comma-separated.
func signerList(doc proposerconfig.Document) string {
	idxs := make([]string, 0, len(doc.Signatures))
	for _, idx := range doc.SignerIndexes() {
		idxs = append(idxs, strconv.Itoa(idx))
	}

	return strings.Join(idxs, ", ")
}

// builderSummary returns the builder block in one line, URL credentials hidden.
func builderSummary(b *proposerconfig.Builder) string {
	if b == nil {
		return "none"
	}

	urls := make([]string, 0, len(b.Builders))
	for _, e := range b.Builders {
		urls = append(urls, proposerconfig.RedactURL(e.URL))
	}

	return fmt.Sprintf("%s · min bid %s gwei · boost factor %s%% · max execution payment %s gwei",
		strings.Join(urls, ", "), b.MinBid, b.BuilderBoostFactor, b.MaxExecutionPayment)
}

func runProposerList(ctx context.Context, w io.Writer, config proposerViewConfig) error {
	lock, doc, err := loadProposerView(ctx, config)
	if err != nil {
		return err
	}

	err = proposerconfig.Verify(doc, lock)
	if err != nil {
		return errors.Wrap(err, "verify proposer config file")
	}

	hash, err := doc.Hash()
	if err != nil {
		return err
	}

	def := doc.Config.DefaultConfig

	_, _ = fmt.Fprintf(w, "Proposer config revision %s, %d validators\n", proposerconfig.RevisionName(doc.Revision, hash), len(lock.Validators))
	_, _ = fmt.Fprintf(w, "Default: fee recipient %s, gas limit %s\n", def.FeeRecipient, def.GasLimit)

	if len(doc.Config.ProposerConfig) == 0 {
		_, _ = fmt.Fprintln(w, "All validators use the default fee recipient.")
	} else {
		_, _ = fmt.Fprintf(w, "%d validator(s) with their own fee recipient:\n", len(doc.Config.ProposerConfig))

		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "  PUBKEY\tFEE RECIPIENT")

		// In lock order, only the validators diverging from the default have an entry.
		for _, val := range lock.Validators {
			pubkey := fmt.Sprintf("%#x", val.PubKey)

			entry, ok := doc.Config.ProposerConfig[pubkey]
			if ok {
				_, _ = fmt.Fprintf(tw, "  %s\t%s\n", pubkey, entry.FeeRecipient)
			}
		}

		_ = tw.Flush()
	}

	_, _ = fmt.Fprintf(w, "Builders: %s\n", builderSummary(def.Builder))

	return nil
}
