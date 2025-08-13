// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"time"

	libp2plog "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/dkg"
)

func newDKGCmd(runFunc func(context.Context, dkg.Config) error) *cobra.Command {
	var config dkg.Config

	cmd := &cobra.Command{
		Use:   "dkg",
		Short: "Participate in a Distributed Key Generation ceremony",
		Long: `Participate in a distributed key generation ceremony for a specific cluster definition that creates
distributed validator key shares and a final cluster lock configuration. Note that all other cluster operators should run
this command at the same time.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { //nolint:revive // keep args variable name for clarity
			if err := log.InitLogger(config.Log); err != nil {
				return err
			}
			libp2plog.SetPrimaryCore(log.LoggerCore()) // Set libp2p logger to use charon logger

			printLicense(cmd.Context())
			printFlags(cmd.Context(), cmd.Flags())

			return runFunc(cmd.Context(), config)
		},
	}

	bindDataDirFlag(cmd.Flags(), &config.DataDir)
	bindKeymanagerFlags(cmd.Flags(), &config.KeymanagerAddr, &config.KeymanagerAuthToken)
	bindDefDirFlag(cmd.Flags(), &config.DefFile)
	bindNoVerifyFlag(cmd.Flags(), &config.NoVerify)
	bindP2PFlags(cmd, &config.P2P)
	bindLogFlags(cmd.Flags(), &config.Log)
	bindPublishFlags(cmd.Flags(), &config)
	bindShutdownDelayFlag(cmd.Flags(), &config.ShutdownDelay)
	bindEth1Flag(cmd.Flags(), &config.ExecutionEngineAddr)

	cmd.Flags().DurationVar(&config.Timeout, "timeout", 1*time.Minute, "Timeout for the DKG process, should be increased if DKG times out.")
	cmd.Flags().BoolVar(&config.Zipped, "zipped", false, "Create a tar archive compressed with gzip of the target directory after creation.")

	return cmd
}

func bindKeymanagerFlags(flags *pflag.FlagSet, addr, authToken *string) {
	flags.StringVar(addr, "keymanager-address", "", "The keymanager URL to import validator keyshares.")
	flags.StringVar(authToken, "keymanager-auth-token", "", "Authentication bearer token to interact with keymanager API. Don't include the \"Bearer\" symbol, only include the api-token.")
}

func bindDefDirFlag(flags *pflag.FlagSet, dataDir *string) {
	flags.StringVar(dataDir, "definition-file", ".charon/cluster-definition.json", "The path to the cluster definition file or an HTTP URL.")
}

func bindDataDirFlag(flags *pflag.FlagSet, dataDir *string) {
	flags.StringVar(dataDir, "data-dir", ".charon", "The directory where charon will store all its internal data.")
}

func bindPublishFlags(flags *pflag.FlagSet, config *dkg.Config) {
	flags.StringVar(&config.PublishAddr, "publish-address", "https://api.obol.tech/v1", "The URL to publish the cluster to.")
	flags.DurationVar(&config.PublishTimeout, "publish-timeout", 30*time.Second, "Timeout for publishing a cluster, consider increasing if the cluster contains more than 200 validators.")
	flags.BoolVar(&config.Publish, "publish", false, "Publish the created cluster to a remote API.")
}

func bindShutdownDelayFlag(flags *pflag.FlagSet, shutdownDelay *time.Duration) {
	flags.DurationVar(shutdownDelay, "shutdown-delay", time.Second, "Graceful shutdown delay.")
}

func bindEth1Flag(flags *pflag.FlagSet, executionEngineAddr *string) {
	flags.StringVar(executionEngineAddr, "execution-client-rpc-endpoint", "", "The address of the execution engine JSON-RPC API.")
}
