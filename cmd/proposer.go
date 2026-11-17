// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
	"github.com/obolnetwork/charon/dkg"
)

// proposerViewConfig is the configuration of the read-only proposer commands: the status and list.
type proposerViewConfig struct {
	LockFile           string
	ProposerConfigFile string
	JSON               bool
}

func newProposerCmd(runStatus func(context.Context, io.Writer, proposerViewConfig), cmds ...*cobra.Command) *cobra.Command {
	var config proposerViewConfig

	cmd := &cobra.Command{
		Use:   "proposer",
		Short: "Show and change the cluster's proposer config: fee recipients, gas limit and builders",
		Long: "Shows the cluster's signed proposer config, the fee recipients, gas limit and builders its validator clients use, and how to change it. " +
			"The subcommands list it per validator, write a change to a proposal file and change it with the other operators.",
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			runStatus(cmd.Context(), cmd.OutOrStdout(), config)
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
		Short: "List the proposer config of each validator",
		Long:  "Lists each validator's fee recipient, whether it is the default or its own, and gas limit, then the builders, which are the same for all validators. Builder URL credentials are hidden.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFunc(cmd.Context(), cmd.OutOrStdout(), config)
		},
	}

	bindProposerViewFlags(cmd, &config)
	cmd.Flags().BoolVar(&config.JSON, "json", false, "Print JSON instead of a table.")

	return cmd
}

func bindProposerViewFlags(cmd *cobra.Command, config *proposerViewConfig) {
	cmd.Flags().StringVar(&config.LockFile, "lock-file", ".charon/cluster-lock.json", "The path to the cluster lock file defining the distributed validator cluster.")
	cmd.Flags().StringVar(&config.ProposerConfigFile, "proposer-config-file", ".charon/vc-config/proposer-config.json", "The path to the proposer config file of any of the cluster's nodes.")
}

// loadProposerView returns the lock and its proposer config document, unverified: the caller checks the document.
func loadProposerView(ctx context.Context, config proposerViewConfig) (cluster.Lock, proposerconfig.Document, error) {
	// Only shown, the document's signatures are verified against it.
	lock, err := dkg.LoadAndVerifyClusterLock(ctx, config.LockFile, "", true)
	if err != nil {
		return cluster.Lock{}, proposerconfig.Document{}, errors.Wrap(err, "load cluster lock")
	}

	doc, err := proposerconfig.LoadAnyNode(config.ProposerConfigFile, *lock)
	if err != nil {
		return *lock, proposerconfig.Document{}, err
	}

	return *lock, doc, nil
}

// runProposerStatus prints the cluster's proposer config and how to change it. It never fails: a problem is printed.
func runProposerStatus(ctx context.Context, w io.Writer, config proposerViewConfig) {
	lock, doc, err := loadProposerView(ctx, config)
	if lock.Name != "" || len(lock.LockHash) > 0 {
		_, _ = fmt.Fprintf(w, "Cluster %q, lock 0x%s…, %d operators, threshold %d\n",
			lock.Name, hex.EncodeToString(lock.LockHash[:4]), len(lock.Operators), lock.Threshold)
	}

	switch {
	case errors.Is(err, proposerconfig.ErrNotFound):
		_, _ = fmt.Fprintf(w, "No proposer config file at %s: charon run writes it from the cluster lock when it starts.\n", config.ProposerConfigFile)
		return
	case err != nil:
		_, _ = fmt.Fprintf(w, "Cannot show the proposer config: %v\n", err)
		return
	}

	if err := proposerconfig.Verify(doc, lock); err != nil {
		_, _ = fmt.Fprintf(w, "Proposer config revision %d does not verify against the cluster lock: %v\n", doc.Revision, err)
	} else if doc.Revision == 0 {
		_, _ = fmt.Fprintln(w, "Proposer config revision 0, unsigned: written from the cluster lock, not yet agreed by the operators")
	} else {
		_, _ = fmt.Fprintf(w, "Proposer config revision %d, signed by %d/%d operators\n", doc.Revision, len(doc.Signatures), len(lock.Operators))
	}

	def := doc.Config.DefaultConfig

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(tw, "  fee recipient\t%s (default), %d validator(s) with their own → charon alpha proposer list\n", def.FeeRecipient, len(doc.Config.ProposerConfig))
	_, _ = fmt.Fprintf(tw, "  gas limit\t%s\n", def.GasLimit)
	_, _ = fmt.Fprintf(tw, "  builders\t%s\n", builderSummary(def.Builder))
	_ = tw.Flush()

	_, _ = fmt.Fprintln(w, "Change it: charon alpha proposer create <change flags>, then every operator runs charon alpha proposer edit <proposal file>")
}

// builderSummary returns the builder block in one line, URL credentials hidden.
func builderSummary(b *proposerconfig.Builder) string {
	if b == nil {
		return "none"
	}

	urls := make([]string, 0, len(b.Builders))
	for _, e := range b.Builders {
		urls = append(urls, log.RedactURL(e.URL, true))
	}

	return fmt.Sprintf("%s · min bid %s gwei · boost factor %s%% · max execution payment %s gwei",
		strings.Join(urls, ", "), b.MinBid, b.BuilderBoostFactor, b.MaxExecutionPayment)
}

// proposerListJSON is the JSON form of the proposer list.
type proposerListJSON struct {
	Revision   uint64                  `json:"revision"`
	Validators []proposerValidatorJSON `json:"validators"`
	Builder    *proposerconfig.Builder `json:"builder"`
}

type proposerValidatorJSON struct {
	Pubkey          string `json:"pubkey"`
	FeeRecipient    string `json:"fee_recipient"`
	OwnFeeRecipient bool   `json:"own_fee_recipient"`
	GasLimit        string `json:"gas_limit"`
}

func runProposerList(ctx context.Context, w io.Writer, config proposerViewConfig) error {
	lock, doc, err := loadProposerView(ctx, config)
	if err != nil {
		return err
	}

	if err := proposerconfig.Verify(doc, lock); err != nil {
		return errors.Wrap(err, "verify proposer config file")
	}

	list := proposerListJSON{Revision: doc.Revision, Builder: redactedBuilder(doc.Config.DefaultConfig.Builder)}

	for _, val := range lock.Validators {
		pubkey := fmt.Sprintf("%#x", val.PubKey)
		_, own := doc.Config.ProposerConfig[pubkey]

		list.Validators = append(list.Validators, proposerValidatorJSON{
			Pubkey:          pubkey,
			FeeRecipient:    doc.Config.FeeRecipient(pubkey),
			OwnFeeRecipient: own,
			GasLimit:        doc.Config.DefaultConfig.GasLimit,
		})
	}

	if config.JSON {
		b, err := json.MarshalIndent(list, "", "  ")
		if err != nil {
			return errors.Wrap(err, "marshal proposer list")
		}

		_, _ = fmt.Fprintln(w, string(b))

		return nil
	}

	_, _ = fmt.Fprintf(w, "Proposer config revision %d\n", list.Revision)

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "INDEX\tPUBKEY\tFEE RECIPIENT\tSOURCE\tGAS LIMIT")

	for i, v := range list.Validators {
		source := "default"
		if v.OwnFeeRecipient {
			source = "own"
		}

		_, _ = fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n", i, v.Pubkey, v.FeeRecipient, source, v.GasLimit)
	}

	_ = tw.Flush()

	_, _ = fmt.Fprintf(w, "Builders of all validators: %s\n", builderSummary(list.Builder))

	return nil
}

// redactedBuilder returns a copy of the builder block with URL credentials hidden.
func redactedBuilder(b *proposerconfig.Builder) *proposerconfig.Builder {
	if b == nil {
		return nil
	}

	out := *b
	out.Builders = make([]proposerconfig.BuilderEntry, 0, len(b.Builders))

	for _, e := range b.Builders {
		e.URL = log.RedactURL(e.URL, true)
		out.Builders = append(out.Builders, e)
	}

	return &out
}
