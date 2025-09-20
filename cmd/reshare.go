// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"os"
	"path/filepath"

	libp2plog "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/dkg"
	"github.com/obolnetwork/charon/dkg/pedersen"
	"github.com/obolnetwork/charon/tbls"
)

func newReshareCmd(runFunc func(context.Context, dkg.ReshareDKGConfig) error) *cobra.Command {
	var config dkg.ReshareDKGConfig

	cmd := &cobra.Command{
		Use:   "reshare",
		Short: "Reshare existing validator keys",
		Long:  `Reshares the existing validator keys retaining the same validator identities.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { //nolint:revive // keep args variable name for clarity
			if err := log.InitLogger(config.DKG.Log); err != nil {
				return err
			}

			libp2plog.SetPrimaryCore(log.LoggerCore()) // Set libp2p logger to use charon logger

			return runFunc(cmd.Context(), config)
		},
	}

	// Bind `reshare` flags.
	cmd.Flags().StringVar(&config.DataDir, "data-dir", ".charon", "The source charon folder with existing cluster data (lock, validator_keys, etc.).")
	cmd.Flags().StringVar(&config.OutputDir, "output-dir", "distributed_validator", "The destination folder for the new cluster data. Must be empty.")

	// Bind `dkg` flags.
	bindNoVerifyFlag(cmd.Flags(), &config.DKG.NoVerify)
	bindP2PFlags(cmd, &config.DKG.P2P)
	bindLogFlags(cmd.Flags(), &config.DKG.Log)
	bindEth1Flag(cmd.Flags(), &config.DKG.ExecutionEngineAddr)
	bindShutdownDelayFlag(cmd.Flags(), &config.DKG.ShutdownDelay)

	return cmd
}

func runReshare(ctx context.Context, conf dkg.ReshareDKGConfig) error {
	if err := validateReshareConfig(ctx, &conf); err != nil {
		return err
	}

	log.Info(ctx, "Running reshare", z.Str("srcDir", conf.DataDir), z.Str("dstDir", conf.OutputDir))

	// Loading the existing cluster lock file.
	lock, err := loadLockJSON(ctx, conf.DataDir, conf.DKG)
	if err != nil {
		return err
	}

	// Loading the existing cluster keystore.
	secrets, err := loadSecrets(ctx, conf.DataDir)
	if err != nil {
		return err
	}

	if len(secrets) != len(lock.Validators) {
		return errors.New("number of private key shares does not match number of validators in cluster lock",
			z.Int("numKeyShares", len(secrets)),
			z.Int("numValidators", len(lock.Validators)))
	}

	log.Info(ctx, "Loaded private key shares", z.Int("numKeys", len(secrets)))

	// Creating dst directory for the new validator keys.
	if err := app.CreateNewEmptyDir(conf.OutputDir); err != nil {
		return err
	}

	if err := app.CopyFile(filepath.Join(conf.DataDir, enrPrivateKeyFile), filepath.Join(conf.OutputDir, enrPrivateKeyFile)); err != nil {
		return err
	}

	log.Info(ctx, "Starting reshare ceremony", z.Str("lockHash", app.Hex7(lock.LockHash)))

	// Preparing the existing shares, but without the PublicShares (we don't persist them).
	// The protocol will reconstruct the PublicShares itself.
	shares := make([]*pedersen.Share, len(secrets))
	for i := range shares {
		shares[i] = &pedersen.Share{
			PubKey:      tbls.PublicKey(lock.Validators[i].PubKey),
			SecretShare: secrets[i],
		}
	}

	if err := dkg.RunReshareDKG(ctx, &conf, lock, shares); err != nil {
		return errors.Wrap(err, "run reshare DKG")
	}

	log.Info(ctx, "Successfully completed reshare ceremony 🎉")
	log.Info(ctx, "IMPORTANT:")
	log.Info(ctx, "You need to shut down your node (charon and VC) and restart it with the new validator keys from: "+conf.OutputDir)

	return nil
}

func validateReshareConfig(ctx context.Context, config *dkg.ReshareDKGConfig) (err error) {
	if config.OutputDir == "" {
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
