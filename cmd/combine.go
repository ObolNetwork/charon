// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/obolnetwork/charon/cmd/combine"
	"github.com/obolnetwork/charon/eth2util"
)

func newCombineCmd(runFunc func(ctx context.Context, clusterDir, outputDir string, force, noverify bool, executionEngineAddr string, testnetConfig eth2util.Network) error) *cobra.Command {
	var (
		clusterDir          string
		outputDir           string
		force               bool
		noverify            bool
		executionEngineAddr string

		testnetConfig eth2util.Network
	)

	cmd := &cobra.Command{
		Use:   "combine",
		Short: "Combine the private key shares of a distributed validator cluster into a set of standard validator private keys",
		Long:  "Combines the private key shares from a threshold of operators in a distributed validator cluster into a set of validator private keys that can be imported into a standard Ethereum validator client.\n\nWarning: running the resulting private keys in a validator alongside the original distributed validator cluster *will* result in slashing.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { //nolint:revive // keep args variable name for clarity
			return runFunc(
				cmd.Context(),
				clusterDir,
				outputDir,
				force,
				noverify,
				executionEngineAddr,
				testnetConfig,
			)
		},
	}

	bindCombineFlags(
		cmd.Flags(),
		&clusterDir,
		&outputDir,
		&force,
		&executionEngineAddr,
		&testnetConfig,
	)

	bindNoVerifyFlag(cmd.Flags(), &noverify)

	return cmd
}

func newCombineFunc(ctx context.Context, clusterDir, outputDir string, force, noverify bool, executionEngineAddr string, testnetConfig eth2util.Network) error {
	return combine.Combine(ctx, clusterDir, outputDir, force, noverify, executionEngineAddr, testnetConfig)
}

func bindCombineFlags(flags *pflag.FlagSet, clusterDir, outputDir *string, force *bool, executionEngineAddr *string, config *eth2util.Network) {
	flags.StringVar(clusterDir, "cluster-dir", ".charon/cluster", `Parent directory containing a number of .charon subdirectories from the required threshold of nodes in the cluster.`)
	flags.StringVar(outputDir, "output-dir", "./validator_keys", "Directory to output the combined private keys to.")
	flags.BoolVar(force, "force", false, "Overwrites private keys with the same name if present.")
	flags.StringVar(executionEngineAddr, "execution-rpc-api", "", "The address of the execution engine JSON-RPC API.")
	flags.StringVar(&config.Name, "testnet-name", "", "Name of the custom test network.")
	flags.StringVar(&config.GenesisForkVersionHex, "testnet-fork-version", "", "Genesis fork version of the custom test network (in hex).")
	flags.Uint64Var(&config.ChainID, "testnet-chain-id", 0, "Chain ID of the custom test network.")
	flags.Int64Var(&config.GenesisTimestamp, "testnet-genesis-timestamp", 0, "Genesis timestamp of the custom test network.")
}
