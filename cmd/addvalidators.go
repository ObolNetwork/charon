// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/json"
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
	SrcDir            string
	DstDir            string
	DKG               dkg.Config
	WithdrawalAddrs   []string
	FeeRecipientAddrs []string
}

func newAddValidatorsCmd(runFunc func(context.Context, addValidatorsConfig) error) *cobra.Command {
	var config addValidatorsConfig

	cmd := &cobra.Command{
		Use:   "add-validators",
		Short: "Add new validators to an existing distributed validator cluster",
		Long:  `Generates and appends new validator keys to an existing distributed validator cluster.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { //nolint:revive // keep args variable name for clarity
			if err := log.InitLogger(config.DKG.Log); err != nil {
				return err
			}

			return runFunc(cmd.Context(), config)
		},
	}

	// Bind `add-validator` flags.
	cmd.Flags().IntVar(&config.NumValidators, "num-validators", 1, "The number of new validators to add to the existing cluster.")
	cmd.Flags().StringVar(&config.SrcDir, "src-dir", ".charon", "The source charon folder with existing cluster data (lock, validator_keys, etc.).")
	cmd.Flags().StringVar(&config.DstDir, "dst-dir", ".charon-add-validators", "Destination (empty) charon folder for combined cluster data. The new cluster data files will be stored here.")

	// Bind `dkg` flags.
	bindKeymanagerFlags(cmd.Flags(), &config.DKG.KeymanagerAddr, &config.DKG.KeymanagerAuthToken)
	bindNoVerifyFlag(cmd.Flags(), &config.DKG.NoVerify)
	bindP2PFlags(cmd, &config.DKG.P2P)
	bindLogFlags(cmd.Flags(), &config.DKG.Log)
	bindPublishFlags(cmd.Flags(), &config.DKG)
	bindShutdownDelayFlag(cmd.Flags(), &config.DKG.ShutdownDelay)
	bindEth1Flag(cmd.Flags(), &config.DKG.ExecutionEngineAddr)
	cmd.Flags().DurationVar(&config.DKG.Timeout, "timeout", 1*time.Minute, "Timeout for the command, should be increased if the command times out.")

	// Bind `create dkg` flags.
	cmd.Flags().StringSliceVar(&config.FeeRecipientAddrs, "fee-recipient-addresses", nil,
		"Comma separated list of Ethereum addresses of the fee recipient for each validator. Either provide a single fee recipient address or fee recipient addresses for each validator.")
	cmd.Flags().StringSliceVar(&config.WithdrawalAddrs, "withdrawal-addresses", nil,
		"Comma separated list of Ethereum addresses to receive the returned stake and accrued rewards for each validator. Either provide a single withdrawal address or withdrawal addresses for each validator.")

	return cmd
}

func runAddValidators(ctx context.Context, conf addValidatorsConfig) error {
	ctx = log.WithTopic(ctx, "add-validators")

	if err := validateConfig(&conf); err != nil {
		return err
	}

	log.Info(ctx, "Running add-validators", z.Int("numValidators", conf.NumValidators), z.Str("srcDir", conf.SrcDir), z.Str("dstDir", conf.DstDir))

	// Loading the existing cluster lock file.
	lockFilePath := filepath.Join(conf.SrcDir, clusterLockFile)

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
	keyStorePath := filepath.Join(conf.SrcDir, validatorKeysSubDir)
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

	// Creating dst directory for the new cluster data and
	// copying ENR private key file to the temporary directory for DKG.
	if err := app.CreateNewEmptyDir(conf.DstDir); err != nil {
		return err
	}

	if err := app.CopyFile(filepath.Join(conf.SrcDir, enrPrivateKeyFile), filepath.Join(conf.DstDir, enrPrivateKeyFile)); err != nil {
		return err
	}

	log.Info(ctx, "Starting add-validators ceremony", z.Int("numValidators", conf.NumValidators), z.Str("lockHash", app.Hex7(lock.LockHash)))

	valAddresses := make([]cluster.ValidatorAddresses, conf.NumValidators)
	for i := range conf.NumValidators {
		valAddresses[i] = cluster.ValidatorAddresses{
			WithdrawalAddress:   conf.WithdrawalAddrs[i],
			FeeRecipientAddress: conf.FeeRecipientAddrs[i],
		}
	}

	dkgConfig := conf.DKG
	dkgConfig.DataDir = conf.DstDir
	dkgConfig.AppendConfig = &dkg.AppendConfig{
		ClusterLock:        &lock,
		SecretShares:       secrets,
		AddValidators:      conf.NumValidators,
		ValidatorAddresses: valAddresses,
	}

	if err := dkg.Run(ctx, dkgConfig); err != nil {
		return errors.Wrap(err, "running dkg with add-validators")
	}

	log.Info(ctx, "Successfully completed add-validators ceremony 🎉")

	log.Info(ctx, "IMPORTANT:")
	log.Info(ctx, "You need to shut down your node (charon and VC) and restart it with the new data directory: "+conf.DstDir)

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

	if config.DstDir == "" {
		return errors.New("dst-dir is required")
	}

	if !app.FileExists(config.SrcDir) {
		return errors.New("src-dir is required")
	}

	lockFile := filepath.Join(config.SrcDir, clusterLockFile)
	if !app.FileExists(lockFile) {
		return errors.New("src-dir must contain a cluster-lock.json file")
	}

	if config.DKG.Publish {
		return errors.New("add-validators does not support --publish flag yet")
	}

	config.FeeRecipientAddrs, config.WithdrawalAddrs, err = validateAddresses(config.NumValidators, config.FeeRecipientAddrs, config.WithdrawalAddrs)

	return err
}
