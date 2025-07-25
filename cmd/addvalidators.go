// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth1wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg"
	"github.com/obolnetwork/charon/eth2util/keystore"
)

const (
	enrPrivateKeyFile   = "charon-enr-private-key"
	clusterLockFile     = "cluster-lock.json"
	validatorKeysSubDir = "validator_keys"
)

// addValidatorsConfig is config for the `add-validators` command.
type addValidatorsConfig struct {
	NumValidators     int
	DataDir           string
	DKG               dkg.Config
	WithdrawalAddrs   []string
	FeeRecipientAddrs []string
}

func newAddValidatorsCmd(runFunc func(context.Context, addValidatorsConfig) error) *cobra.Command {
	var config addValidatorsConfig

	cmd := &cobra.Command{
		Use:   "add-validators",
		Short: "Creates and adds new validators to a distributed validator cluster",
		Long:  `Creates and adds new validators to a distributed validator cluster. It generates keys for new validators and appends them to the existing cluster.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { //nolint:revive // keep args variable name for clarity
			if err := log.InitLogger(config.DKG.Log); err != nil {
				return err
			}

			return runFunc(cmd.Context(), config)
		},
	}

	bindAddValidatorsFlags(cmd, &config)

	// Bind DKG flags.
	bindKeymanagerFlags(cmd.Flags(), &config.DKG.KeymanagerAddr, &config.DKG.KeymanagerAuthToken)
	bindNoVerifyFlag(cmd.Flags(), &config.DKG.NoVerify)
	bindP2PFlags(cmd, &config.DKG.P2P)
	bindLogFlags(cmd.Flags(), &config.DKG.Log)
	bindPublishFlags(cmd.Flags(), &config.DKG)
	bindShutdownDelayFlag(cmd.Flags(), &config.DKG.ShutdownDelay)
	bindEth1Flag(cmd.Flags(), &config.DKG.ExecutionEngineAddr)
	cmd.Flags().DurationVar(&config.DKG.Timeout, "timeout", 1*time.Minute, "Timeout for the command, should be increased if the command times out.")

	// Create DKG flags.
	cmd.Flags().StringSliceVar(&config.FeeRecipientAddrs, "fee-recipient-addresses", nil, "Comma separated list of Ethereum addresses of the fee recipient for each validator. Either provide a single fee recipient address or fee recipient addresses for each validator.")
	cmd.Flags().StringSliceVar(&config.WithdrawalAddrs, "withdrawal-addresses", nil, "Comma separated list of Ethereum addresses to receive the returned stake and accrued rewards for each validator. Either provide a single withdrawal address or withdrawal addresses for each validator.")

	return cmd
}

// bindAddValidatorsFlags binds command line flags for the `add-validators` command.
func bindAddValidatorsFlags(cmd *cobra.Command, config *addValidatorsConfig) {
	cmd.Flags().IntVar(&config.NumValidators, "num-validators", 1, "The number of new validators to add to the existing cluster.")
	cmd.Flags().StringVar(&config.DataDir, "data-dir", ".charon", "The existing charon data folder with cluster-lock.json, validator_keys, etc.")
}

func runAddValidators(ctx context.Context, conf addValidatorsConfig) error {
	ctx = log.WithTopic(ctx, "add-validators")

	if err := validateConfig(&conf); err != nil {
		return err
	}

	if err := validatePermissions(ctx, conf.DataDir); err != nil {
		return err
	}

	// Loading the existing cluster lock file.
	lockFilePath := filepath.Join(conf.DataDir, clusterLockFile)

	b, err := os.ReadFile(lockFilePath)
	if err != nil {
		return errors.Wrap(err, "read cluster-lock.json", z.Str("path", lockFilePath))
	}

	var lock cluster.Lock
	if err := json.Unmarshal(b, &lock); err != nil {
		return errors.Wrap(err, "unmarshal cluster-lock.json", z.Str("path", lockFilePath))
	}

	if err := verifyLock(ctx, lock, conf.DKG); err != nil {
		return err
	}

	// Loading the existing cluster keystore.
	keyStorePath := filepath.Join(conf.DataDir, validatorKeysSubDir)
	log.Info(ctx, "Loading keystore", z.Str("path", keyStorePath))

	privateKeyFiles, err := keystore.LoadFilesUnordered(keyStorePath)
	if err != nil {
		return errors.Wrap(err, "cannot load private key share", z.Str("path", keyStorePath))
	}

	secrets, err := privateKeyFiles.SequencedKeys()
	if err != nil {
		return errors.Wrap(err, "order private key shares")
	}

	log.Info(ctx, "Loaded private key shares", z.Int("numKeys", len(secrets)))

	log.Info(ctx, "Starting add-validators ceremony", z.Int("numValidators", conf.NumValidators), z.Str("lockHash", app.Hex7(lock.LockHash)))

	// DKG will be run in a temporary directory to avoid conflicts with existing data.
	dkgDir := filepath.Join(os.TempDir(), fmt.Sprintf("charon-merge-%d", os.Getpid()))
	if err := os.MkdirAll(dkgDir, 0o700); err != nil {
		return errors.Wrap(err, "create temp dir", z.Str("path", dkgDir))
	}
	// defer os.RemoveAll(dkgDir) // Clean up the temporary directory after DKG is done.

	// Copying ENR private key file to the temporary directory for DKG.
	srcKeyPath := filepath.Join(conf.DataDir, enrPrivateKeyFile)

	dstKeyPath := filepath.Join(dkgDir, enrPrivateKeyFile)
	if err := app.CopyFile(srcKeyPath, dstKeyPath); err != nil {
		return err
	}

	log.Info(ctx, "Using temporary directory for DKG", z.Str("dir", dkgDir))

	valAddresses := make([]cluster.ValidatorAddresses, conf.NumValidators)
	for i := range conf.NumValidators {
		valAddresses[i] = cluster.ValidatorAddresses{
			WithdrawalAddress:   conf.WithdrawalAddrs[i],
			FeeRecipientAddress: conf.FeeRecipientAddrs[i],
		}
	}

	dkgConfig := conf.DKG
	dkgConfig.DataDir = dkgDir
	dkgConfig.AppendConfig = &dkg.AppendConfig{
		ClusterLock:        &lock,
		SecretShares:       secrets,
		AddValidators:      conf.NumValidators,
		ValidatorAddresses: valAddresses,
	}

	if err := dkg.Run(ctx, dkgConfig); err != nil {
		return errors.Wrap(err, "running dkg+append")
	}

	log.Info(ctx, "Successfully completed add-validators ceremony 🎉")
	log.Info(ctx, "You must restart your node (charon and VC) to apply the changes!")

	return nil
}

func verifyLock(ctx context.Context, lock cluster.Lock, conf dkg.Config) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	eth1Cl := eth1wrap.NewDefaultEthClientRunner(conf.ExecutionEngineAddr)
	go eth1Cl.Run(ctx)

	if err := lock.VerifyHashes(); err != nil && !conf.NoVerify {
		return errors.Wrap(err, "cluster lock hashes verification failed. Run with --no-verify to bypass verification at own risk")
	} else if err != nil && conf.NoVerify {
		log.Warn(ctx, "Ignoring failed cluster lock hashes verification due to --no-verify flag", err)
	}

	if err := lock.VerifySignatures(eth1Cl); err != nil && !conf.NoVerify {
		return errors.Wrap(err, "cluster lock signature verification failed. Run with --no-verify to bypass verification at own risk")
	} else if err != nil && conf.NoVerify {
		log.Warn(ctx, "Ignoring failed cluster lock signature verification due to --no-verify flag", err)
	}

	return nil
}

func validateConfig(config *addValidatorsConfig) (err error) {
	if config.NumValidators <= 0 {
		return errors.New("num-validators must be greater than 0")
	}

	if !app.FileExists(config.DataDir) {
		return errors.New("data-dir is required")
	}

	lockFile := filepath.Join(config.DataDir, clusterLockFile)
	if !app.FileExists(lockFile) {
		return errors.New("data-dir must contain a cluster-lock.json file")
	}

	if config.DKG.Publish {
		return errors.New("add-validators does not support --publish flag yet")
	}

	config.FeeRecipientAddrs, config.WithdrawalAddrs, err = validateAddresses(config.NumValidators, config.FeeRecipientAddrs, config.WithdrawalAddrs)

	return err
}

func validatePermissions(ctx context.Context, dataDir string) error {
	canWriteToDir, err := app.CheckDirectoryWritePermission(dataDir)
	if err != nil {
		return errors.Wrap(err, "checking data-dir permissions")
	}

	if !canWriteToDir {
		log.Info(ctx, "Add write permissions to data-dir: chmod u+wx "+dataDir)

		return errors.New("data-dir must be writable")
	}

	lockFile := filepath.Join(dataDir, clusterLockFile)

	canRewrite, err := app.CanRewriteFile(lockFile)
	if err != nil {
		return errors.Wrap(err, "checking cluster-lock.json permissions")
	}

	if !canRewrite {
		log.Info(ctx, "Add write permissions to cluster-lock.json: chmod u+w "+lockFile)

		return errors.New("cluster-lock.json must be writable")
	}

	return nil
}
