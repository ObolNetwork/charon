// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
	"github.com/obolnetwork/charon/dkg"
	"github.com/obolnetwork/charon/eth2util/enr"
)

const (
	defaultAlphaRelay = "https://4.relay.obol.dev"
)

func newAddOperatorsCmd(runFunc func(context.Context, dkg.AddOperatorsConfig, dkg.Config) error) *cobra.Command {
	var (
		config    dkg.AddOperatorsConfig
		dkgConfig dkg.Config
	)

	cmd := &cobra.Command{
		Use:   "add-operators",
		Short: "Add new operators to an existing distributed validator cluster",
		Long:  `Adds new operators to an existing distributed validator cluster, keeping validator public keys unchanged.`,
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
	cmd.Flags().StringSliceVar(&config.NewENRs, "new-operator-enrs", nil, "Comma-separated list of the new operators to be added (Charon ENR addresses).")
	cmd.Flags().DurationVar(&dkgConfig.Timeout, "timeout", time.Minute, "Timeout for the protocol, should be increased if protocol times out.")

	bindNoVerifyFlag(cmd.Flags(), &dkgConfig.NoVerify)
	bindP2PFlags(cmd, &dkgConfig.P2P, defaultAlphaRelay)
	bindLogFlags(cmd.Flags(), &dkgConfig.Log)
	bindEth1Flag(cmd.Flags(), &dkgConfig.ExecutionEngineAddr)
	bindShutdownDelayFlag(cmd.Flags(), &dkgConfig.ShutdownDelay)
	bindPublishFlags(cmd.Flags(), &dkgConfig)

	return cmd
}

func runAddOperators(ctx context.Context, config dkg.AddOperatorsConfig, dkgConfig dkg.Config) error {
	if err := validateAddOperatorsConfig(ctx, &config, &dkgConfig); err != nil {
		return err
	}

	log.Info(ctx, "Starting add-operators ceremony", z.Str("lockFilePath", config.LockFilePath), z.Str("outputDir", config.OutputDir))

	if err := dkg.RunAddOperatorsProtocol(ctx, config, dkgConfig); err != nil {
		return errors.Wrap(err, "run add operators protocol")
	}

	log.Info(ctx, "Successfully completed add-operators ceremony 🎉")
	log.Info(ctx, "IMPORTANT:")
	log.Info(ctx, "You need to shut down your node (charon and VC) and restart it with the new data directory: "+config.OutputDir)

	return nil
}

func validateAddOperatorsConfig(ctx context.Context, config *dkg.AddOperatorsConfig, dkgConfig *dkg.Config) error {
	if config.OutputDir == "" {
		return errors.New("output-dir is required")
	}

	if len(config.NewENRs) == 0 {
		return errors.New("new-operator-enrs is required")
	}

	if !app.FileExists(config.LockFilePath) {
		return errors.New("lock-file does not exist")
	}

	if dkgConfig.Timeout < time.Minute {
		return errors.New("timeout must be at least 1 minute")
	}

	if hasDuplicateENRs(config.NewENRs) {
		return errors.New("new-operator-enrs contains duplicate ENRs")
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
	isNewOperator := slices.Contains(config.NewENRs, thisENR)

	for _, o := range lock.Operators {
		if slices.Contains(config.NewENRs, o.ENR) {
			return errors.New("new-operator-enrs contains an existing operator", z.Str("enr", o.ENR))
		}
	}

	if !isNewOperator {
		secrets, err := dkg.LoadSecrets(config.ValidatorKeysDir)
		if err != nil {
			return err
		}

		if len(secrets) != lock.NumValidators {
			return errors.New("the number of secret keys does not match the number of validators in the cluster lock")
		}
	}

	return nil
}

func hasDuplicateENRs(enrs []string) bool {
	seen := make(map[string]struct{})
	for _, e := range enrs {
		if _, ok := seen[e]; ok {
			return true
		}

		seen[e] = struct{}{}
	}

	return false
}
