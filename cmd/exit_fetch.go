// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	libp2plog "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/keystore"
)

func newFetchExitCmd(runFunc func(context.Context, exitConfig) error) *cobra.Command {
	var config exitConfig

	cmd := &cobra.Command{
		Use:   "fetch",
		Short: "Fetch a signed exit message from the remote API",
		Long:  `Fetches a fully signed exit message for a given validator from the remote API and writes it to disk.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := log.InitLogger(config.Log); err != nil {
				return err
			}
			libp2plog.SetPrimaryCore(log.LoggerCore()) // Set libp2p logger to use charon logger

			printFlags(cmd.Context(), cmd.Flags())

			return runFunc(cmd.Context(), config)
		},
	}

	bindExitFlags(cmd, &config, []exitCLIFlag{
		{publishAddress, false},
		{privateKeyPath, false},
		{lockFilePath, false},
		{validatorPubkey, false},
		{all, false},
		{fetchedExitPath, false},
		{publishTimeout, false},
		{testnetName, false},
		{testnetForkVersion, false},
		{testnetChainID, false},
		{testnetGenesisTimestamp, false},
		{testnetCapellaHardFork, false},
	})

	bindLogFlags(cmd.Flags(), &config.Log)

	wrapPreRunE(cmd, func(cmd *cobra.Command, _ []string) error {
		valPubkPresent := cmd.Flags().Lookup(validatorPubkey.String()).Changed

		if !valPubkPresent && !config.All {
			//nolint:revive,perfsprint // we use our own version of the errors package; keep consistency with other checks.
			return errors.New(fmt.Sprintf("%s must be specified when exiting single validator.", validatorPubkey.String()))
		}

		if config.All && valPubkPresent {
			//nolint:revive // we use our own version of the errors package.
			return errors.New(fmt.Sprintf("%s should not be specified when %s is, as it is obsolete and misleading.", validatorPubkey.String(), all.String()))
		}

		return nil
	})

	return cmd
}

func runFetchExit(ctx context.Context, config exitConfig) error {
	// Check if custom testnet configuration is provided.
	if config.testnetConfig.IsNonZero() {
		// Add testnet config to supported networks.
		eth2util.AddTestNetwork(config.testnetConfig)
	}

	if _, err := os.Stat(config.FetchedExitPath); err != nil {
		return errors.Wrap(err, "store exit path")
	}

	writeTestFile := filepath.Join(config.FetchedExitPath, ".write-test")
	if err := os.WriteFile(writeTestFile, []byte{}, 0o755); err != nil { //nolint:gosec // write test file
		return errors.Wrap(err, "can't write to destination directory")
	}

	if err := os.Remove(writeTestFile); err != nil {
		return errors.Wrap(err, "can't delete write test file")
	}

	identityKey, err := k1util.Load(config.PrivateKeyPath)
	if err != nil {
		return errors.Wrap(err, "could not load identity key")
	}

	cl, err := loadClusterManifest("", config.LockFilePath)
	if err != nil {
		return errors.Wrap(err, "could not load cluster-lock.json")
	}

	oAPI, err := obolapi.New(config.PublishAddress, obolapi.WithTimeout(config.PublishTimeout))
	if err != nil {
		return errors.Wrap(err, "could not create obol api client")
	}

	shareIdx, err := keystore.ShareIdxForCluster(cl, *identityKey.PubKey())
	if err != nil {
		return errors.Wrap(err, "could not determine operator index from cluster lock for supplied identity key")
	}

	if config.All {
		for _, validator := range cl.GetValidators() {
			validatorPubKeyHex := fmt.Sprintf("0x%x", validator.GetPublicKey())

			valCtx := log.WithCtx(ctx, z.Str("validator", validatorPubKeyHex))

			log.Info(valCtx, "Retrieving full exit message")

			fullExit, err := oAPI.GetFullExit(valCtx, validatorPubKeyHex, cl.GetInitialMutationHash(), shareIdx, identityKey)
			if err != nil {
				return errors.Wrap(err, "could not load full exit data from Obol API")
			}

			err = writeExitToFile(valCtx, validatorPubKeyHex, config.FetchedExitPath, fullExit)
			if err != nil {
				return err
			}
		}
	} else {
		validator := core.PubKey(config.ValidatorPubkey)
		if _, err := validator.Bytes(); err != nil {
			return errors.Wrap(err, "cannot convert validator pubkey to bytes")
		}

		ctx = log.WithCtx(ctx, z.Str("validator", validator.String()))

		log.Info(ctx, "Retrieving full exit message")

		fullExit, err := oAPI.GetFullExit(ctx, config.ValidatorPubkey, cl.GetInitialMutationHash(), shareIdx, identityKey)
		if err != nil {
			return errors.Wrap(err, "could not load full exit data from Obol API")
		}

		err = writeExitToFile(ctx, config.ValidatorPubkey, config.FetchedExitPath, fullExit)
		if err != nil {
			return err
		}
	}

	return nil
}

func writeExitToFile(ctx context.Context, valPubKey string, exitPath string, fullExit obolapi.ExitBlob) error {
	fetchedExitFname := fmt.Sprintf("exit-%s.json", valPubKey)
	fetchedExitPath := filepath.Join(exitPath, fetchedExitFname)

	exitData, err := json.Marshal(fullExit.SignedExitMessage)
	if err != nil {
		return errors.Wrap(err, "signed exit message marshal")
	}

	if err := os.WriteFile(fetchedExitPath, exitData, 0o600); err != nil {
		return errors.Wrap(err, "store signed exit message")
	}

	log.Info(ctx, "Stored signed exit message", z.Str("path", fetchedExitPath))

	return nil
}
