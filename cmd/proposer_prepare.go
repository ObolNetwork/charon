// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/dkg"
)

func newProposerPrepareCmd(runFunc func(context.Context, io.Writer, dkg.ProposerConfigProposalConfig) error) *cobra.Command {
	var (
		config  dkg.ProposerConfigProposalConfig
		logConf log.Config
		flags   proposerChangeFlags
	)

	cmd := &cobra.Command{
		Use:   "prepare",
		Short: "Prepare the proposal file of a proposer config change, for the operators to run edit with",
		Long: "Prepares a proposal file: the cluster's next proposer config revision with the change flags applied. " +
			"It is to charon alpha proposer edit what charon create dkg's cluster definition is to charon dkg: one person prepares it and sends it to every operator, who all run the ceremony with it. " +
			"It needs the cluster lock and the proposer config file of any of its nodes, but no node key, so its author need not be an operator. It signs and changes nothing.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := log.InitLogger(logConf); err != nil {
				return err
			}

			delta, err := flags.delta(cmd)
			if err != nil {
				return err
			}

			config.Delta = delta

			return runFunc(cmd.Context(), cmd.OutOrStdout(), config)
		},
	}

	f := cmd.Flags()
	flags.bind(f)
	f.StringVar(&config.OutputFile, "output-file", "proposer-config-proposal.json", "The path to write the proposal file to, it must not exist.")
	f.StringVar(&config.LockFilePath, "lock-file", ".charon/cluster-lock.json", "The path to the cluster lock file defining the distributed validator cluster.")
	f.StringVar(&config.ProposerConfigFile, "proposer-config-file", ".charon/vc-config/proposer-config.json", "The path to the proposer config file of any of the cluster's nodes.")
	f.StringVar(&config.OverridesFile, "overrides-file", ".charon/builder_registrations_overrides.json", "The path to the builder registration overrides file, a revision 0 proposer config file is compared with.")
	bindNoVerifyFlag(f, &config.NoVerify)
	bindLogFlags(f, &logConf)
	bindEth1Flag(f, &config.ExecutionEngineAddr)

	markHidden(f, "overrides-file", "no-verify", "execution-client-rpc-endpoint")

	return cmd
}

func runProposerPrepare(ctx context.Context, w io.Writer, conf dkg.ProposerConfigProposalConfig) error {
	change, err := dkg.WriteProposerConfigProposal(ctx, conf)
	if err != nil {
		return err
	}

	printProposerConfigChange(w, change)

	_, _ = fmt.Fprintf(w, "Proposal written to %s. Nothing is changed yet: send it to the operators, then all run charon alpha proposer edit %s.\n",
		conf.OutputFile, conf.OutputFile)

	return nil
}
