// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"

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
		Short: "Sign partial exit message for a distributed validator.",
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

	bindGenericExitFlags(cmd, &config)
	bindExitRelatedFlags(cmd, &config)
	bindLogFlags(cmd.Flags(), &config.Log)

	return cmd
}

func runSignPartialExit(ctx context.Context, config exitConfig) error {
	identityKey, err := k1util.Load(config.PrivateKeyPath)
	if err != nil {
		return errors.Wrap(err, "could not load identity key")
	}

	cl, err := loadClusterManifest("", config.LockFilePath)
	if err != nil {
		return errors.Wrap(err, "could not load cluster data")
	}

	rawValKeys, err := keystore.LoadFilesUnordered(config.ValidatorKeysDir)
	if err != nil {
		return errors.Wrap(err, "could not load keystore")
	}

	valKeys, err := rawValKeys.SequencedKeys()
	if err != nil {
		return errors.Wrap(err, "could not load keystore")
	}

	shares, err := keystore.KeysharesToValidatorPubkey(cl, valKeys)
	if err != nil {
		return errors.Wrap(err, "could not match keyshares with their counterparty in cluster manifest")
	}

	validator := core.PubKey(config.ValidatorPubkey)

	valEth2, err := validator.ToETH2()
	if err != nil {
		return errors.Wrap(err, "cannot convert validator pubkey to bytes")
	}

	ctx = log.WithCtx(ctx, z.Str("validator", validator.String()))

	shareIdx, err := keystore.ShareIdxForCluster(cl, *identityKey.PubKey())
	if err != nil {
		return errors.Wrap(err, "could not load share index from cluster lock")
	}

	ourShare, ok := shares[validator]
	if !ok {
		return errors.New("validator not present in cluster manifest", z.Str("validator", validator.String()))
	}

	eth2Cl, err := eth2Client(ctx, config.BeaconNodeURL)
	if err != nil {
		return errors.Wrap(err, "cannot create eth2 client for specified beacon node")
	}

	oAPI, err := obolapi.New(config.PublishAddress)
	if err != nil {
		return errors.Wrap(err, "could not create obol api client")
	}

	log.Info(ctx, "Signing exit message for validator")

	rawValData, err := eth2Cl.Validators(ctx, &eth2api.ValidatorsOpts{
		PubKeys: []eth2p0.BLSPubKey{
			valEth2,
		},
		State: "head",
	})
	if err != nil {
		return errors.Wrap(err, "cannot fetch validator index")
	}

	valData := rawValData.Data

	var valIndex eth2p0.ValidatorIndex
	var valIndexFound bool

	for _, val := range valData {
		if val.Validator.PublicKey == valEth2 {
			valIndex = val.Index
			valIndexFound = true

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
		PublicKey:         config.ValidatorPubkey,
		SignedExitMessage: exitMsg,
	}

	if err := oAPI.PostPartialExit(ctx, cl.GetInitialMutationHash(), shareIdx, identityKey, exitBlob); err != nil {
		return errors.Wrap(err, "could not POST partial exit message to Obol API")
	}

	return nil
}
