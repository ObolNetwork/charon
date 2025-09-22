// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"path/filepath"
	"time"

	libp2plog "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/dkg"
)

func newRemoveOperatorsCmd(runFunc func(context.Context, dkg.RemoveOperatorsConfig, dkg.Config) error) *cobra.Command {
	var (
		config    dkg.RemoveOperatorsConfig
		dkgConfig dkg.Config
	)

	cmd := &cobra.Command{
		Use:   "remove-operators",
		Short: "Remove operators from an existing distributed validator cluster",
		Long:  `Removes operators from an existing distributed validator cluster, leaving all validators intact.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { //nolint:revive // keep args variable name for clarity
			if err := log.InitLogger(dkgConfig.Log); err != nil {
				return err
			}
			libp2plog.SetPrimaryCore(log.LoggerCore()) // Set libp2p logger to use charon logger

			return runFunc(cmd.Context(), config, dkgConfig)
		},
	}

	cmd.Flags().StringVar(&dkgConfig.DataDir, "data-dir", ".charon", "The source charon folder with existing cluster data (lock, validator_keys, etc.).")
	cmd.Flags().StringVar(&config.OutputDir, "output-dir", "distributed_validator", "The destination folder for the new cluster data. Must be empty. Optional for removed operators.")
	cmd.Flags().StringSliceVar(&config.OldENRs, "old-operator-enrs", nil, "Comma-separated list of operators to be removed (Charon ENR addresses).")
	cmd.Flags().IntVar(&config.NewThreshold, "new-threshold", 0, "The new threshold for the cluster. Evaluated automatically when not specified. All operators must agree on the same value.")
	cmd.Flags().DurationVar(&dkgConfig.Timeout, "timeout", time.Minute, "Timeout for the protocol, should be increased if protocol times out.")

	bindNoVerifyFlag(cmd.Flags(), &dkgConfig.NoVerify)
	bindP2PFlags(cmd, &dkgConfig.P2P)
	bindLogFlags(cmd.Flags(), &dkgConfig.Log)
	bindEth1Flag(cmd.Flags(), &dkgConfig.ExecutionEngineAddr)
	bindShutdownDelayFlag(cmd.Flags(), &dkgConfig.ShutdownDelay)

	return cmd
}

func runRemoveOperators(ctx context.Context, config dkg.RemoveOperatorsConfig, dkgConfig dkg.Config) error {
	if err := validateRemoveOperatorsConfig(&config, &dkgConfig); err != nil {
		return err
	}

	log.Info(ctx, "Starting remove-operators ceremony", z.Str("dataDir", dkgConfig.DataDir), z.Str("outputDir", config.OutputDir))

	if err := dkg.RunRemoveOperatorsProtocol(ctx, config, dkgConfig); err != nil {
		return errors.Wrap(err, "run remove operators protocol")
	}

	log.Info(ctx, "Successfully completed remove-operators ceremony 🎉")
	log.Info(ctx, "IMPORTANT:")
	log.Info(ctx, "You need to shut down your node (charon and VC) and restart it with the new data directory: "+config.OutputDir)

	return nil
}

func validateRemoveOperatorsConfig(config *dkg.RemoveOperatorsConfig, dkgConfig *dkg.Config) error {
	if len(config.OldENRs) == 0 {
		return errors.New("old-operator-enrs is required")
	}

	if !app.FileExists(dkgConfig.DataDir) {
		return errors.New("data-dir is required")
	}

	lockFile := filepath.Join(dkgConfig.DataDir, clusterLockFile)
	if !app.FileExists(lockFile) {
		return errors.New("data-dir must contain a cluster-lock.json file")
	}

	return nil
}
