// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

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
	JSON               bool
}

func newProposerCmd(runStatus func(context.Context, io.Writer, proposerViewConfig), cmds ...*cobra.Command) *cobra.Command {
	var config proposerViewConfig

	cmd := &cobra.Command{
		Use:   "proposer",
		Short: "Show and change the cluster's proposer config: fee recipients, gas limit and builders",
		Long: "Shows the cluster's signed proposer config, the fee recipients, gas limit and builders its validator clients use, and how to change it. " +
			"To change it, all operators run edit at the same time with the same change: either the same change flags, or a proposal file one person wrote with create, which spares everyone retyping the flags.",
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
		Short: "List the default proposer config and the validators with their own fee recipient",
		Long: "Lists the default fee recipient and gas limit, the validators whose fee recipient differs from the default, and the builders. " +
			"Validators on the default are counted, not listed. Builder URL credentials are hidden.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFunc(cmd.Context(), cmd.OutOrStdout(), config)
		},
	}

	bindProposerViewFlags(cmd, &config)
	cmd.Flags().BoolVar(&config.JSON, "json", false, "Print JSON instead of a table.")

	return cmd
}

// bindProposerAPIFlags binds the Obol API address and timeout of publishing and fetching the proposer config.
func bindProposerAPIFlags(f *pflag.FlagSet, addr *string, timeout *time.Duration) {
	f.StringVar(addr, "publish-address", "https://api.obol.tech/v1", "The URL of the Obol API the proposer config is published to.")
	f.DurationVar(timeout, "publish-timeout", defaultPublishTimeout, "Timeout for the Obol API request.")
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

// runProposerStatus prints the cluster's proposer config and how to change it. It never fails: a problem is printed.
func runProposerStatus(ctx context.Context, w io.Writer, config proposerViewConfig) {
	lock, doc, err := loadProposerView(ctx, config)
	if len(lock.Operators) > 0 {
		_, _ = fmt.Fprintf(w, "Cluster %q, lock 0x%s…, %d operators, threshold %d\n",
			lock.Name, hex.EncodeToString(lock.LockHash[:min(4, len(lock.LockHash))]), len(lock.Operators), lock.Threshold)
	}

	switch {
	case errors.Is(err, proposerconfig.ErrNotFound):
		_, _ = fmt.Fprintf(w, "No proposer config file at %s: charon run writes it from the cluster lock when it starts.\n", config.ProposerConfigFile)
		return
	case err != nil:
		_, _ = fmt.Fprintf(w, "Cannot show the proposer config: %v\n", err)
		return
	}

	// An unverified document is not shown, its content cannot be trusted.
	err = proposerconfig.Verify(doc, lock)
	if err != nil {
		_, _ = fmt.Fprintf(w, "Proposer config revision %d does not verify against the cluster lock: %v\n", doc.Revision, err)
		return
	}

	if doc.Revision == 0 {
		_, _ = fmt.Fprintln(w, "Proposer config revision 0, unsigned: written from the cluster lock, not yet agreed by the operators")
	} else {
		_, _ = fmt.Fprintf(w, "Proposer config revision %d, signed by %d of %d operators: %s\n",
			doc.Revision, len(doc.Signatures), len(lock.Operators), signerList(doc))
	}

	def := doc.Config.DefaultConfig

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(tw, "  fee recipient\t%s (default), %d validator(s) with their own → charon alpha proposer list\n", def.FeeRecipient, len(doc.Config.ProposerConfig))
	_, _ = fmt.Fprintf(tw, "  gas limit\t%s\n", def.GasLimit)
	_, _ = fmt.Fprintf(tw, "  builders\t%s\n", builderSummary(def.Builder))
	_ = tw.Flush()

	_, _ = fmt.Fprintln(w, "Change it: every operator runs charon alpha proposer edit <change flags> at the same time, or edit <proposal file> with a file from charon alpha proposer create")
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

// proposerListJSON is the JSON form of the proposer list.
type proposerListJSON struct {
	Revision   uint64                  `json:"revision"`
	Validators int                     `json:"validators"`
	Default    proposerDefaultJSON     `json:"default"`
	Own        []proposerOwnJSON       `json:"own_fee_recipients"`
	Builder    *proposerconfig.Builder `json:"builder"`
}

type proposerDefaultJSON struct {
	FeeRecipient string `json:"fee_recipient"`
	GasLimit     string `json:"gas_limit"`
}

// proposerOwnJSON is a validator whose fee recipient differs from the default.
type proposerOwnJSON struct {
	Pubkey       string `json:"pubkey"`
	FeeRecipient string `json:"fee_recipient"`
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

	def := doc.Config.DefaultConfig
	list := proposerListJSON{
		Revision:   doc.Revision,
		Validators: len(lock.Validators),
		Default:    proposerDefaultJSON{FeeRecipient: def.FeeRecipient, GasLimit: def.GasLimit},
		Own:        []proposerOwnJSON{},
		Builder:    redactedBuilder(def.Builder),
	}

	// In lock order, only the validators diverging from the default have an entry.
	for _, val := range lock.Validators {
		pubkey := fmt.Sprintf("%#x", val.PubKey)

		entry, ok := doc.Config.ProposerConfig[pubkey]
		if ok {
			list.Own = append(list.Own, proposerOwnJSON{Pubkey: pubkey, FeeRecipient: entry.FeeRecipient})
		}
	}

	if config.JSON {
		b, err := json.MarshalIndent(list, "", "  ")
		if err != nil {
			return errors.Wrap(err, "marshal proposer list")
		}

		_, _ = fmt.Fprintln(w, string(b))

		return nil
	}

	_, _ = fmt.Fprintf(w, "Proposer config revision %d, %d validators\n", list.Revision, list.Validators)
	_, _ = fmt.Fprintf(w, "Default: fee recipient %s, gas limit %s\n", list.Default.FeeRecipient, list.Default.GasLimit)

	if len(list.Own) == 0 {
		_, _ = fmt.Fprintln(w, "All validators use the default fee recipient.")
	} else {
		_, _ = fmt.Fprintf(w, "%d validator(s) with their own fee recipient:\n", len(list.Own))

		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "  PUBKEY\tFEE RECIPIENT")

		for _, v := range list.Own {
			_, _ = fmt.Fprintf(tw, "  %s\t%s\n", v.Pubkey, v.FeeRecipient)
		}

		_ = tw.Flush()
	}

	_, _ = fmt.Fprintf(w, "Builders: %s\n", builderSummary(list.Builder))

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
		e.URL = proposerconfig.RedactURL(e.URL)
		out.Builders = append(out.Builders, e)
	}

	return &out
}
