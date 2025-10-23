// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"os"
	"time"

	libp2plog "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/dkg"
)

func newRecreatePrivateKeysCmd(runFunc func(context.Context, dkg.ReshareConfig) error) *cobra.Command {
	var config dkg.ReshareConfig

	cmd := &cobra.Command{
		Use:   "recreate-private-keys",
		Short: "Create new private key shares to replace existing validator private key shares",
		Long:  `Creates new private key shares to replace the existing validator private keys while retaining the same operator identities.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { //nolint:revive // keep args variable name for clarity
			if err := log.InitLogger(config.DKGConfig.Log); err != nil {
				return err
			}

			libp2plog.SetPrimaryCore(log.LoggerCore()) // Set libp2p logger to use charon logger

			return runFunc(cmd.Context(), config)
		},
	}

	cmd.Flags().StringVar(&config.OutputDir, "output-dir", "distributed_validator", "The destination folder for the new cluster artifacts. Must be empty.")
	cmd.Flags().StringVar(&config.PrivateKeyPath, "private-key-file", ".charon/charon-enr-private-key", "The path to the charon enr private key file. ")
	cmd.Flags().StringVar(&config.LockFilePath, "lock-file", ".charon/cluster-lock.json", "The path to the cluster lock file defining the distributed validator cluster.")
	cmd.Flags().StringVar(&config.ValidatorKeysDir, "validator-keys-dir", ".charon/validator_keys", "Path to the directory containing the validator private key share files and passwords.")
	cmd.Flags().DurationVar(&config.DKGConfig.Timeout, "timeout", time.Minute, "Timeout for the protocol, should be increased if protocol times out.")

	bindNoVerifyFlag(cmd.Flags(), &config.DKGConfig.NoVerify)
	bindP2PFlags(cmd, &config.DKGConfig.P2P, defaultAlphaRelay)
	bindLogFlags(cmd.Flags(), &config.DKGConfig.Log)
	bindEth1Flag(cmd.Flags(), &config.DKGConfig.ExecutionEngineAddr)
	bindShutdownDelayFlag(cmd.Flags(), &config.DKGConfig.ShutdownDelay)

	return cmd
}

func runRecreatePrivateKeys(ctx context.Context, config dkg.ReshareConfig) error {
	if err := validateReshareConfig(config); err != nil {
		return err
	}

	log.Info(ctx, "Starting reshare ceremony", z.Str("lockFilePath", config.LockFilePath), z.Str("outputDir", config.OutputDir))

	if err := dkg.RunReshareProtocol(ctx, config); err != nil {
		return errors.Wrap(err, "run reshare protocol")
	}

	log.Info(ctx, "Successfully completed reshare ceremony 🎉")
	log.Info(ctx, "IMPORTANT:")
	log.Info(ctx, "You need to shut down your node (charon and VC) and restart it with the new data directory: "+config.OutputDir)

	return nil
}

func validateReshareConfig(config dkg.ReshareConfig) (err error) {
	if config.OutputDir == "" {
		return errors.New("output-dir is required")
	}

	if !app.FileExists(config.LockFilePath) {
		return errors.New("lock-file is required")
	}

	if !app.FileExists(config.PrivateKeyPath) {
		return errors.New("private-key-file is required")
	}

	if config.ValidatorKeysDir == "" {
		return errors.New("validator-keys-dir is required")
	}

	keyFiles, err := os.ReadDir(config.ValidatorKeysDir)

	validatorKeysDirPresent := err == nil && len(keyFiles) > 0
	if !validatorKeysDirPresent {
		return errors.New("validator-keys-dir empty")
	}

	if config.DKGConfig.Timeout < time.Minute {
		return errors.New("timeout must be at least 1 minute")
	}

	return nil
}
