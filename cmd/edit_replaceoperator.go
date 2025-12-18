// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"os"
	"slices"
	"time"

	libp2plog "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg"
	"github.com/obolnetwork/charon/eth2util/enr"
)

func newReplaceOperatorCmd(runFunc func(context.Context, dkg.ReplaceOperatorConfig, dkg.Config) error) *cobra.Command {
	var (
		config    dkg.ReplaceOperatorConfig
		dkgConfig dkg.Config
	)

	cmd := &cobra.Command{
		Use:   "replace-operator",
		Short: "Replace an operator in an existing distributed validator cluster",
		Long:  `Replaces an operator in an existing distributed validator cluster, keeping validator public keys unchanged.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { //nolint:revive // keep args variable name for clarity
			if err := log.InitLogger(dkgConfig.Log); err != nil {
				return err
			}

			libp2plog.SetPrimaryCore(log.LoggerCore()) // Set libp2p logger to use charon logger

			return runFunc(cmd.Context(), config, dkgConfig)
		},
	}

	cmd.Flags().StringVar(&config.PrivateKeyPath, "private-key-file", ".charon/charon-enr-private-key", "The path to the charon enr private key file. ")
	cmd.Flags().StringVar(&config.LockFilePath, "lock-file", ".charon/cluster-lock.json", "The path to the cluster lock file defining the distributed validator cluster.")
	cmd.Flags().StringVar(&config.ValidatorKeysDir, "validator-keys-dir", ".charon/validator_keys", "Path to the directory containing the validator private key share files and passwords.")
	cmd.Flags().StringVar(&config.OutputDir, "output-dir", "distributed_validator", "The destination folder for the new cluster data. Must be empty.")
	cmd.Flags().StringVar(&config.NewENR, "new-operator-enr", "", "The new operator to be added (Charon ENR address).")
	cmd.Flags().StringVar(&config.OldENR, "old-operator-enr", "", "The old operator to be replaced (Charon ENR address).")
	cmd.Flags().DurationVar(&dkgConfig.Timeout, "timeout", time.Minute, "Timeout for the protocol, should be increased if protocol times out.")

	bindNoVerifyFlag(cmd.Flags(), &dkgConfig.NoVerify)
	bindP2PFlags(cmd, &dkgConfig.P2P, defaultAlphaRelay)
	bindLogFlags(cmd.Flags(), &dkgConfig.Log)
	bindEth1Flag(cmd.Flags(), &dkgConfig.ExecutionEngineAddr)
	bindShutdownDelayFlag(cmd.Flags(), &dkgConfig.ShutdownDelay)

	return cmd
}

func runReplaceOperator(ctx context.Context, config dkg.ReplaceOperatorConfig, dkgConfig dkg.Config) error {
	if err := validateReplaceOperatorConfig(ctx, &config, &dkgConfig); err != nil {
		return err
	}

	log.Info(ctx, "Starting replace-operator ceremony", z.Str("lockFilePath", config.LockFilePath), z.Str("outputDir", config.OutputDir))

	if err := dkg.RunReplaceOperatorProtocol(ctx, config, dkgConfig); err != nil {
		return errors.Wrap(err, "run replace operator protocol")
	}

	log.Info(ctx, "Successfully completed replace-operator ceremony 🎉")
	log.Info(ctx, "IMPORTANT:")
	log.Info(ctx, "You need to shut down your node (charon and VC) and restart it with the new data directory: "+config.OutputDir)

	return nil
}

func validateReplaceOperatorConfig(ctx context.Context, config *dkg.ReplaceOperatorConfig, dkgConfig *dkg.Config) error {
	if config.OutputDir == "" {
		return errors.New("output-dir is required")
	}

	if len(config.NewENR) == 0 {
		return errors.New("new-operator-enr is required")
	}

	if len(config.OldENR) == 0 {
		return errors.New("old-operator-enr is required")
	}

	if config.OldENR == config.NewENR {
		return errors.New("old-operator-enr and new-operator-enr cannot be the same")
	}

	if !app.FileExists(config.LockFilePath) {
		return errors.New("lock-file does not exist")
	}

	if dkgConfig.Timeout < time.Minute {
		return errors.New("timeout must be at least 1 minute")
	}

	lock, err := dkg.LoadAndVerifyClusterLock(ctx, config.LockFilePath, dkgConfig.ExecutionEngineAddr, dkgConfig.NoVerify)
	if err != nil {
		return err
	}

	key, err := dkg.LoadPrivKey(config.PrivateKeyPath)
	if err != nil {
		return err
	}

	r, err := enr.New(key)
	if err != nil {
		return err
	}

	thisENR := r.String()

	if config.OldENR == thisENR {
		return errors.New("the old-operator-enr shall not participate in the ceremony")
	}

	for _, o := range lock.Operators {
		if o.ENR == config.NewENR {
			return errors.New("new-operator-enr matches an existing operator", z.Str("enr", config.NewENR))
		}
	}

	containsOldENR := slices.ContainsFunc(lock.Operators, func(op cluster.Operator) bool {
		return op.ENR == config.OldENR
	})
	if !containsOldENR {
		return errors.New("old-operator-enr does not match any existing operator in the cluster lock")
	}

	// Validate validator keys based on node role
	if config.NewENR == thisENR {
		// New operator should not have existing validator keys
		entries, err := os.ReadDir(config.ValidatorKeysDir)
		if err != nil && !os.IsNotExist(err) {
			return errors.Wrap(err, "read validator keys directory")
		}

		if len(entries) > 0 {
			return errors.New("new operator should not have existing validator keys")
		}
	} else if config.OldENR != thisENR {
		// Continuing operators must have validator keys
		secrets, err := dkg.LoadSecrets(config.ValidatorKeysDir)
		if err != nil {
			return errors.Wrap(err, "load validator keys")
		}

		if len(secrets) != lock.NumValidators {
			return errors.New("number of secret keys does not match validators in cluster lock")
		}
	}

	return nil
}
