// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"fmt"
	"strings"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	libp2plog "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util/keystore"
)

func newSubmitPartialExitCmd(runFunc func(context.Context, exitConfig) error) *cobra.Command {
	var config exitConfig

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign partial exit message for a distributed validator",
		Long:  `Sign a partial exit message for a distributed validator and submit it to a remote API for aggregation.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
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
		{validatorKeysDir, false},
		{exitEpoch, false},
		{validatorPubkey, false},
		{validatorIndex, false},
		{beaconNodeEndpoints, true},
		{beaconNodeTimeout, false},
	})

	bindLogFlags(cmd.Flags(), &config.Log)

	wrapPreRunE(cmd, func(cmd *cobra.Command, _ []string) error {
		valIdxPresent := cmd.Flags().Lookup(validatorIndex.String()).Changed
		if strings.TrimSpace(config.ValidatorPubkey) == "" && !valIdxPresent {
			//nolint:revive // we use our own version of the errors package.
			return errors.New(fmt.Sprintf("%s or %s must be specified.", validatorIndex.String(), validatorPubkey.String()))
		}

		config.ValidatorIndexPresent = valIdxPresent

		return nil
	})

	return cmd
}

func runSignPartialExit(ctx context.Context, config exitConfig) error {
	identityKey, err := k1util.Load(config.PrivateKeyPath)
	if err != nil {
		return errors.Wrap(err, "could not load identity key")
	}

	cl, err := loadClusterManifest("", config.LockFilePath)
	if err != nil {
		return errors.Wrap(err, "could not load cluster-lock.json")
	}

	rawValKeys, err := keystore.LoadFilesUnordered(config.ValidatorKeysDir)
	if err != nil {
		return errors.Wrap(err, "could not load keystore, check if path exists", z.Str("path", config.ValidatorKeysDir))
	}

	valKeys, err := rawValKeys.SequencedKeys()
	if err != nil {
		return errors.Wrap(err, "could not load keystore")
	}

	shares, err := keystore.KeysharesToValidatorPubkey(cl, valKeys)
	if err != nil {
		return errors.Wrap(err, "could not match local validator key shares with their counterparty in cluster lock")
	}

	validator := core.PubKey(config.ValidatorPubkey)

	valEth2, err := validator.ToETH2()
	if err != nil && !config.ValidatorIndexPresent {
		return errors.Wrap(err, "cannot convert validator pubkey to bytes")
	}

	if config.ValidatorIndexPresent {
		ctx = log.WithCtx(ctx, z.U64("validator_index", config.ValidatorIndex))
	} else {
		ctx = log.WithCtx(ctx, z.Str("validator", validator.String()))
	}

	shareIdx, err := keystore.ShareIdxForCluster(cl, *identityKey.PubKey())
	if err != nil {
		return errors.Wrap(err, "could not determine operator index from cluster lock for supplied identity key")
	}

	ourShare, ok := shares[validator]
	if !ok && !config.ValidatorIndexPresent {
		return errors.New("validator not present in cluster lock", z.Str("validator", validator.String()))
	}

	eth2Cl, err := eth2Client(ctx, config.BeaconNodeEndpoints, config.BeaconNodeTimeout)
	if err != nil {
		return errors.Wrap(err, "cannot create eth2 client for specified beacon node")
	}

	eth2Cl.SetForkVersion([4]byte(cl.GetForkVersion()))

	oAPI, err := obolapi.New(config.PublishAddress, obolapi.WithTimeout(config.PublishTimeout))
	if err != nil {
		return errors.Wrap(err, "could not create obol api client")
	}

	log.Info(ctx, "Signing exit message for validator")

	var valIndex eth2p0.ValidatorIndex
	var valIndexFound bool

	valAPICallOpts := &eth2api.ValidatorsOpts{
		State: "head",
	}

	if config.ValidatorIndexPresent {
		valAPICallOpts.Indices = []eth2p0.ValidatorIndex{
			eth2p0.ValidatorIndex(config.ValidatorIndex),
		}
	} else {
		valAPICallOpts.PubKeys = []eth2p0.BLSPubKey{
			valEth2,
		}
	}

	rawValData, err := eth2Cl.Validators(ctx, valAPICallOpts)
	if err != nil {
		return errors.Wrap(err, "cannot fetch validator")
	}

	valData := rawValData.Data

	for _, val := range valData {
		if val.Validator.PublicKey == valEth2 || val.Index == eth2p0.ValidatorIndex(config.ValidatorIndex) {
			valIndex = val.Index
			valIndexFound = true

			// re-initialize state variable after looking up all the necessary details, since user only provided a validator index
			if config.ValidatorIndexPresent {
				valEth2 = val.Validator.PublicKey
				ourShare, ok = shares[core.PubKeyFrom48Bytes(valEth2)]
				if !ok && !config.ValidatorIndexPresent {
					return errors.New("validator not present in cluster lock", z.U64("validator_index", config.ValidatorIndex), z.Str("validator", validator.String()))
				}
			}

			break
		}
	}

	if !valIndexFound {
		return errors.New("validator index not found in beacon node response")
	}

	exitMsg, err := signExit(ctx, eth2Cl, valIndex, ourShare.Share, eth2p0.Epoch(config.ExitEpoch))
	if err != nil {
		return errors.Wrap(err, "cannot sign partial exit message")
	}

	exitBlob := obolapi.ExitBlob{
		PublicKey:         valEth2.String(),
		SignedExitMessage: exitMsg,
	}

	if err := oAPI.PostPartialExit(ctx, cl.GetInitialMutationHash(), shareIdx, identityKey, exitBlob); err != nil {
		return errors.Wrap(err, "could not POST partial exit message to Obol API")
	}

	return nil
}
