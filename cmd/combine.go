// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/obolnetwork/charon/combine"
)

func newCombineCmd(runFunc func(ctx context.Context, clusterDir string, force bool) error) *cobra.Command {
	var (
		clusterDir string
		force      bool
	)

	cmd := &cobra.Command{
		Use:   "combine",
		Short: "Combines the private key shares of a distributed validator cluster into a set of standard validator private keys.",
		Long:  "Combines the private key shares from a threshold of operators in a distributed validator cluster into a set of validator private keys that can be imported into a standard Ethereum validator client.\n\nWarning: running the resulting private keys in a validator alongside the original distributed validator cluster *will* result in slashing.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFunc(cmd.Context(), clusterDir, force)
		},
	}

	bindCombineFlags(
		cmd.Flags(),
		&clusterDir,
		&force,
	)

	return cmd
}

func newCombineFunc(ctx context.Context, clusterDir string, force bool) error {
	return combine.Combine(ctx, clusterDir, force)
}

func bindCombineFlags(flags *pflag.FlagSet, clusterDir *string, force *bool) {
	flags.StringVar(clusterDir, "cluster-dir", ".charon/", `Parent directory containing a number of .charon subdirectories from each node in the cluster.`)
	flags.BoolVar(force, "force", false, "Overwrites private keys with the same name if present.")
}
