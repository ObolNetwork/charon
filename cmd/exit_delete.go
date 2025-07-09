// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"fmt"

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

func newDeleteExitCmd(runFunc func(context.Context, exitConfig) error) *cobra.Command {
	var config exitConfig

	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a signed exit message from the remote API",
		Long:  `Deletes a partially signed exit message for a given validator from the remote API.`,
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

func runDeleteExit(ctx context.Context, config exitConfig) error {
	// Check if custom testnet configuration is provided.
	if config.testnetConfig.IsNonZero() {
		// Add testnet config to supported networks.
		eth2util.AddTestNetwork(config.testnetConfig)
	}

	identityKey, err := k1util.Load(config.PrivateKeyPath)
	if err != nil {
		return errors.Wrap(err, "load identity key", z.Str("private_key_path", config.PrivateKeyPath))
	}

	cl, err := loadClusterManifest("", config.LockFilePath)
	if err != nil {
		return errors.Wrap(err, "load cluster lock", z.Str("lock_file_path", config.LockFilePath))
	}

	oAPI, err := obolapi.New(config.PublishAddress, obolapi.WithTimeout(config.PublishTimeout))
	if err != nil {
		return errors.Wrap(err, "create Obol API client", z.Str("publish_address", config.PublishAddress))
	}

	shareIdx, err := keystore.ShareIdxForCluster(cl, *identityKey.PubKey())
	if err != nil {
		return errors.Wrap(err, "determine operator index from cluster lock for supplied identity key")
	}

	if config.All {
		for _, validator := range cl.GetValidators() {
			validatorPubKeyHex := fmt.Sprintf("0x%x", validator.GetPublicKey())

			valCtx := log.WithCtx(ctx, z.Str("validator", validatorPubKeyHex))

			log.Info(ctx, "Deleting partial exit message")

			err := oAPI.DeletePartialExit(valCtx, validatorPubKeyHex, cl.GetInitialMutationHash(), shareIdx, identityKey)
			if err != nil {
				if errors.Is(err, obolapi.ErrNoExit) {
					log.Warn(ctx, fmt.Sprintf("partial exit data from Obol API for validator %v not available (exit may not have been submitted)", validatorPubKeyHex), nil)
					continue
				}

				return errors.Wrap(err, "delete partial exits for all validators from public key")
			}

		}
	} else {
		validator := core.PubKey(config.ValidatorPubkey)
		if _, err := validator.Bytes(); err != nil {
			return errors.Wrap(err, "convert validator pubkey to bytes", z.Str("validator_public_key", config.ValidatorPubkey))
		}

		ctx = log.WithCtx(ctx, z.Str("validator", validator.String()))

		log.Info(ctx, "Deleting partial exit message")

		err := oAPI.DeletePartialExit(ctx, config.ValidatorPubkey, cl.GetInitialMutationHash(), shareIdx, identityKey)
		if err != nil {
			return errors.Wrap(err, "delete partial exit data from Obol API", z.Str("validator_public_key", config.ValidatorPubkey))
		}
	}

	return nil
}
