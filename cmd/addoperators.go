// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"path/filepath"
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
	"github.com/obolnetwork/charon/p2p"
)

func newAddOperatorsCmd(runFunc func(context.Context, dkg.AddOperatorsConfig, dkg.Config) error) *cobra.Command {
	var (
		config    dkg.AddOperatorsConfig
		dkgConfig dkg.Config
	)

	cmd := &cobra.Command{
		Use:   "add-operators",
		Short: "Add new operators to an existing distributed validator cluster",
		Long:  `Adds new operators to an existing distributed validator cluster, leaving all validators intact.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { //nolint:revive // keep args variable name for clarity
			if err := log.InitLogger(dkgConfig.Log); err != nil {
				return err
			}

			libp2plog.SetPrimaryCore(log.LoggerCore()) // Set libp2p logger to use charon logger

			return runFunc(cmd.Context(), config, dkgConfig)
		},
	}

	cmd.Flags().StringVar(&dkgConfig.DataDir, "data-dir", ".charon", "The source charon folder with existing cluster data (lock, validator_keys, etc.). The new operators will only have the lock and enr private key files.")
	cmd.Flags().StringVar(&config.OutputDir, "output-dir", "distributed_validator", "The destination folder for the new cluster data. Must be empty.")
	cmd.Flags().StringSliceVar(&config.NewENRs, "new-operator-enrs", nil, "Comma-separated list of the new operators to be added (Charon ENR addresses).")
	cmd.Flags().IntVar(&config.NewThreshold, "new-threshold", 0, "The new threshold for the cluster. Evaluated automatically when not specified. All operators (old and new) must agree on the same value.")
	cmd.Flags().DurationVar(&dkgConfig.Timeout, "timeout", time.Minute, "Timeout for the protocol, should be increased if protocol times out.")

	bindNoVerifyFlag(cmd.Flags(), &dkgConfig.NoVerify)
	bindP2PFlags(cmd, &dkgConfig.P2P)
	bindLogFlags(cmd.Flags(), &dkgConfig.Log)
	bindEth1Flag(cmd.Flags(), &dkgConfig.ExecutionEngineAddr)
	bindShutdownDelayFlag(cmd.Flags(), &dkgConfig.ShutdownDelay)

	return cmd
}

func runAddOperators(ctx context.Context, config dkg.AddOperatorsConfig, dkgConfig dkg.Config) error {
	if err := validateAddOperatorsConfig(ctx, &config, &dkgConfig); err != nil {
		return err
	}

	log.Info(ctx, "Starting add-operators ceremony", z.Str("dataDir", dkgConfig.DataDir), z.Str("outputDir", config.OutputDir))

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

	if !app.FileExists(dkgConfig.DataDir) {
		return errors.New("data-dir is required")
	}

	lockFile := filepath.Join(dkgConfig.DataDir, clusterLockFile)
	if !app.FileExists(lockFile) {
		return errors.New("data-dir must contain a cluster-lock.json file")
	}

	if dkgConfig.Timeout < time.Minute {
		return errors.New("timeout must be at least 1 minute")
	}

	if hasDuplicateENRs(config.NewENRs) {
		return errors.New("new-operator-enrs contains duplicate ENRs")
	}

	lock, err := dkg.LoadAndVerifyClusterLock(ctx, *dkgConfig)
	if err != nil {
		return err
	}

	key, err := p2p.LoadPrivKey(dkgConfig.DataDir)
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

	newN := len(lock.Operators) + len(config.NewENRs)
	newT := newN - (newN-1)/3

	if config.NewThreshold != 0 {
		if config.NewThreshold >= newN || config.NewThreshold < newT {
			return errors.New("new-threshold is invalid", z.Int("recommendedThreshold", newT))
		}
	}

	if !isNewOperator {
		secrets, err := dkg.LoadSecrets(dkgConfig.DataDir)
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
