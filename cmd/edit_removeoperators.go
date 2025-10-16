// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
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

	cmd.Flags().StringVar(&config.PrivateKeyPath, "private-key-file", ".charon/charon-enr-private-key", "The path to the charon enr private key file. ")
	cmd.Flags().StringVar(&config.LockFilePath, "lock-file", ".charon/cluster-lock.json", "The path to the cluster lock file defining the distributed validator cluster.")
	cmd.Flags().StringVar(&config.ValidatorKeysDir, "validator-keys-dir", ".charon/validator_keys", "Path to the directory containing the validator private key share files and passwords.")
	cmd.Flags().StringVar(&config.OutputDir, "output-dir", "distributed_validator", "The destination folder for the new cluster data. Must be empty. Optional for removed operators.")
	cmd.Flags().StringSliceVar(&config.RemovingENRs, "operator-enrs-to-remove", nil, "Comma-separated list of operators to be removed (Charon ENR addresses).")
	cmd.Flags().IntVar(&config.NewThreshold, "new-threshold", 0, "Optional override of the new threshold required for signature reconstruction. Defaults to ceil(n*2/3) if zero. Warning, non-default values decrease security. All operators must use the same value.")
	cmd.Flags().DurationVar(&dkgConfig.Timeout, "timeout", time.Minute, "Timeout for the protocol, should be increased if protocol times out.")
	cmd.Flags().StringSliceVar(&config.ParticipatingENRs, "participating-operator-enrs", nil, "Comma-separated list of operator ENRs participating in the ceremony. Required if --operator-enrs-to-remove specifies more operators to remove than the fault tolerance of the current cluster.")

	bindNoVerifyFlag(cmd.Flags(), &dkgConfig.NoVerify)
	bindP2PFlags(cmd, &dkgConfig.P2P, defaultAlphaRelay)
	bindLogFlags(cmd.Flags(), &dkgConfig.Log)
	bindEth1Flag(cmd.Flags(), &dkgConfig.ExecutionEngineAddr)
	bindShutdownDelayFlag(cmd.Flags(), &dkgConfig.ShutdownDelay)

	return cmd
}

func runRemoveOperators(ctx context.Context, config dkg.RemoveOperatorsConfig, dkgConfig dkg.Config) error {
	if err := validateRemoveOperatorsConfig(ctx, &config, &dkgConfig); err != nil {
		return err
	}

	log.Info(ctx, "Starting remove-operators ceremony", z.Str("lockFilePath", config.LockFilePath), z.Str("outputDir", config.OutputDir))

	if err := dkg.RunRemoveOperatorsProtocol(ctx, config, dkgConfig); err != nil {
		return errors.Wrap(err, "run remove operators protocol")
	}

	log.Info(ctx, "Successfully completed remove-operators ceremony 🎉")
	log.Info(ctx, "IMPORTANT:")
	log.Info(ctx, "You need to shut down your node (charon and VC) and restart it with the new data directory: "+config.OutputDir)

	return nil
}

func validateRemoveOperatorsConfig(ctx context.Context, config *dkg.RemoveOperatorsConfig, dkgConfig *dkg.Config) error {
	if len(config.RemovingENRs) == 0 {
		return errors.New("operator-enrs-to-remove is required")
	}

	if !app.FileExists(config.LockFilePath) {
		return errors.New("lock-file does not exist")
	}

	if dkgConfig.Timeout < time.Minute {
		return errors.New("timeout must be at least 1 minute")
	}

	if hasDuplicateENRs(config.RemovingENRs) {
		return errors.New("operator-enrs-to-remove contains duplicate ENRs")
	}

	if hasDuplicateENRs(config.ParticipatingENRs) {
		return errors.New("participating-operator-enrs contains duplicate ENRs")
	}

	lock, err := dkg.LoadAndVerifyClusterLock(ctx, config.LockFilePath, dkgConfig.ExecutionEngineAddr, dkgConfig.NoVerify)
	if err != nil {
		return err
	}

	ok := slices.ContainsFunc(lock.Operators, func(o cluster.Operator) bool {
		return slices.Contains(config.RemovingENRs, o.ENR)
	})
	if !ok {
		return errors.New("operator-enrs-to-remove contains a non-existing operator")
	}

	if len(config.ParticipatingENRs) > 0 {
		ok := slices.ContainsFunc(lock.Operators, func(o cluster.Operator) bool {
			return slices.Contains(config.ParticipatingENRs, o.ENR)
		})
		if !ok {
			return errors.New("participating-operator-enrs contains a non-existing operator")
		}
	}

	f := len(lock.Operators) - lock.Threshold
	if len(config.RemovingENRs) > f && len(config.ParticipatingENRs) == 0 {
		return errors.New("participating-operator-enrs is required when after the removal, the remaining amount of operators is below the current threshold")
	}

	if len(config.RemovingENRs) > f && len(config.ParticipatingENRs) < lock.Threshold {
		return errors.New("not enough participating operators to complete the protocol, need at least threshold participants")
	}

	thisENR, err := dkg.LoadMyENR(config.PrivateKeyPath)
	if err != nil {
		return err
	}

	if slices.Contains(config.RemovingENRs, thisENR) && !slices.Contains(config.ParticipatingENRs, thisENR) {
		return errors.New("enrs being removed cannot participate unless specified in participating-operator-enrs")
	}

	newN := len(lock.Operators) - len(config.RemovingENRs)
	newT := newN - (newN-1)/3

	if config.NewThreshold != 0 {
		if config.NewThreshold >= newN || config.NewThreshold < newT {
			return errors.New("new-threshold is invalid", z.Int("recommendedThreshold", newT))
		}
	}

	secrets, err := dkg.LoadSecrets(config.ValidatorKeysDir)
	if err != nil {
		return err
	}

	if len(secrets) != lock.NumValidators {
		return errors.New("the number of secret keys does not match the number of validators in the cluster lock")
	}

	return nil
}
