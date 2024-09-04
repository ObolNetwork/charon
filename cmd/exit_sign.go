// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"fmt"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	libp2plog "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
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
		RunE: func(cmd *cobra.Command, args []string) error { //nolint:revive // keep args variable name for clarity
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
		{publishTimeout, false},
	})

	bindLogFlags(cmd.Flags(), &config.Log)

	wrapPreRunE(cmd, func(cmd *cobra.Command, _ []string) error {
		valIdxPresent := cmd.Flags().Lookup(validatorIndex.String()).Changed
		valPubkPresent := cmd.Flags().Lookup(validatorPubkey.String()).Changed

		if !valPubkPresent && !valIdxPresent {
			//nolint:revive // we use our own version of the errors package.
			return errors.New(fmt.Sprintf("either %s or %s must be specified at least.", validatorIndex.String(), validatorPubkey.String()))
		}

		config.ValidatorIndexPresent = valIdxPresent
		config.SkipBeaconNodeCheck = valIdxPresent && valPubkPresent

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

	shareIdx, err := keystore.ShareIdxForCluster(cl, *identityKey.PubKey())
	if err != nil {
		return errors.Wrap(err, "could not determine operator index from cluster lock for supplied identity key")
	}

	oAPI, err := obolapi.New(config.PublishAddress, obolapi.WithTimeout(config.PublishTimeout))
	if err != nil {
		return errors.Wrap(err, "could not create obol api client")
	}

	eth2Cl, err := eth2Client(ctx, config.BeaconNodeEndpoints, config.BeaconNodeTimeout, [4]byte(cl.GetForkVersion()))
	if err != nil {
		return errors.Wrap(err, "cannot create eth2 client for specified beacon node")
	}

	if config.ValidatorIndexPresent {
		ctx = log.WithCtx(ctx, z.U64("validator_index", config.ValidatorIndex))
	}
	if config.ValidatorPubkey != "" {
		ctx = log.WithCtx(ctx, z.Str("validator_pubkey", config.ValidatorPubkey))
	}

	if config.SkipBeaconNodeCheck {
		log.Info(ctx, "Both public key and index are specified, beacon node won't be checked for validator existence/liveness")
	}

	valEth2, err := fetchValidatorBLSPubKey(ctx, config, eth2Cl)
	if err != nil {
		return errors.Wrap(err, "cannot fetch validator public key")
	}

	validator := core.PubKeyFrom48Bytes(valEth2)

	ourShare, ok := shares[validator]
	if !ok {
		return errors.New("validator not present in cluster lock", z.Str("validator", validator.String()))
	}

	valIndex, err := fetchValidatorIndex(ctx, config, eth2Cl)
	if err != nil {
		return errors.Wrap(err, "cannot fetch validator index")
	}

	log.Info(ctx, "Signing exit message for validator")

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

func fetchValidatorBLSPubKey(ctx context.Context, config exitConfig, eth2Cl eth2wrap.Client) (eth2p0.BLSPubKey, error) {
	if config.ValidatorPubkey != "" {
		valEth2, err := core.PubKey(config.ValidatorPubkey).ToETH2()
		if err != nil {
			return eth2p0.BLSPubKey{}, errors.Wrap(err, "cannot convert validator pubkey to bytes")
		}

		return valEth2, nil
	}

	valAPICallOpts := &eth2api.ValidatorsOpts{
		State:   "head",
		Indices: []eth2p0.ValidatorIndex{eth2p0.ValidatorIndex(config.ValidatorIndex)},
	}

	rawValData, err := eth2Cl.Validators(ctx, valAPICallOpts)
	if err != nil {
		return eth2p0.BLSPubKey{}, errors.Wrap(err, "cannot fetch validators")
	}

	for _, val := range rawValData.Data {
		if val.Index == eth2p0.ValidatorIndex(config.ValidatorIndex) {
			return val.Validator.PublicKey, nil
		}
	}

	return eth2p0.BLSPubKey{}, errors.New("validator index not found in beacon node response")
}

func fetchValidatorIndex(ctx context.Context, config exitConfig, eth2Cl eth2wrap.Client) (eth2p0.ValidatorIndex, error) {
	if config.ValidatorIndexPresent {
		return eth2p0.ValidatorIndex(config.ValidatorIndex), nil
	}

	valEth2, err := core.PubKey(config.ValidatorPubkey).ToETH2()
	if err != nil {
		return 0, errors.Wrap(err, "cannot convert validator pubkey to bytes")
	}

	valAPICallOpts := &eth2api.ValidatorsOpts{
		State:   "head",
		PubKeys: []eth2p0.BLSPubKey{valEth2},
	}

	rawValData, err := eth2Cl.Validators(ctx, valAPICallOpts)
	if err != nil {
		return 0, errors.Wrap(err, "cannot fetch validators")
	}

	for _, val := range rawValData.Data {
		if val.Validator.PublicKey == valEth2 {
			return val.Index, nil
		}
	}

	return 0, errors.New("validator public key not found in beacon node response")
}
