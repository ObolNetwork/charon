// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"os"
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

func newReshareCmd(runFunc func(context.Context, string, dkg.Config) error) *cobra.Command {
	var (
		config    dkg.Config
		outputDir string
	)

	cmd := &cobra.Command{
		Use:   "reshare",
		Short: "Reshare existing validator keys",
		Long:  `Reshares the existing validator keys retaining the same validator identities.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { //nolint:revive // keep args variable name for clarity
			if err := log.InitLogger(config.Log); err != nil {
				return err
			}

			libp2plog.SetPrimaryCore(log.LoggerCore()) // Set libp2p logger to use charon logger

			return runFunc(cmd.Context(), outputDir, config)
		},
	}

	cmd.Flags().StringVar(&outputDir, "output-dir", "distributed_validator", "The destination folder for the new cluster artifacts. Must be empty.")
	cmd.Flags().StringVar(&config.DataDir, "data-dir", ".charon", "The source charon folder with existing cluster data (lock, validator_keys, etc.).")
	cmd.Flags().DurationVar(&config.Timeout, "timeout", time.Minute, "Timeout for the protocol, should be increased if protocol times out.")

	bindNoVerifyFlag(cmd.Flags(), &config.NoVerify)
	bindP2PFlags(cmd, &config.P2P)
	bindLogFlags(cmd.Flags(), &config.Log)
	bindEth1Flag(cmd.Flags(), &config.ExecutionEngineAddr)
	bindShutdownDelayFlag(cmd.Flags(), &config.ShutdownDelay)

	return cmd
}

func runReshare(ctx context.Context, outputDir string, config dkg.Config) error {
	if err := validateReshareConfig(ctx, outputDir, config); err != nil {
		return err
	}

	log.Info(ctx, "Starting reshare ceremony", z.Str("dataDir", config.DataDir), z.Str("outputDir", outputDir))

	if err := dkg.RunReshareProtocol(ctx, outputDir, config); err != nil {
		return errors.Wrap(err, "run reshare protocol")
	}

	log.Info(ctx, "Successfully completed reshare ceremony 🎉")
	log.Info(ctx, "IMPORTANT:")
	log.Info(ctx, "You need to shut down your node (charon and VC) and restart it with the new validator keys from: "+outputDir)

	return nil
}

func validateReshareConfig(ctx context.Context, outputDir string, config dkg.Config) (err error) {
	if outputDir == "" {
		return errors.New("output-dir is required")
	}

	if !app.FileExists(config.DataDir) {
		return errors.New("data-dir is required")
	}

	lockFile := filepath.Join(config.DataDir, clusterLockFile)
	if !app.FileExists(lockFile) {
		return errors.New("data-dir must contain a cluster-lock.json file")
	}

	validatorKeysDir := filepath.Join(config.DataDir, validatorKeysSubDir)

	keyFiles, err := os.ReadDir(validatorKeysDir)

	validatorKeysDirPresent := err == nil && len(keyFiles) > 0
	if !validatorKeysDirPresent {
		log.Error(ctx, "The validator_keys directory is empty.", nil)

		return errors.New("data-dir must contain a non-empty validator_keys directory")
	}

	return nil
}
