// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"fmt"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
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
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/keystore"
)

func newSignPartialExitCmd(runFunc func(context.Context, exitConfig) error) *cobra.Command {
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
		{all, false},
		{testnetName, false},
		{testnetForkVersion, false},
		{testnetChainID, false},
		{testnetGenesisTimestamp, false},
		{testnetCapellaHardFork, false},
		{beaconNodeHeaders, false},
		{fallbackBeaconNodeAddrs, false},
	})

	bindLogFlags(cmd.Flags(), &config.Log)

	wrapPreRunE(cmd, func(cmd *cobra.Command, _ []string) error {
		valIdxPresent := cmd.Flags().Lookup(validatorIndex.String()).Changed
		valPubkPresent := cmd.Flags().Lookup(validatorPubkey.String()).Changed

		if !valPubkPresent && !valIdxPresent && !config.All {
			//nolint:revive // we use our own version of the errors package.
			return errors.New(fmt.Sprintf("either %s or %s must be specified at least when exiting single validator.", validatorIndex.String(), validatorPubkey.String()))
		}

		if config.All && (valIdxPresent || valPubkPresent) {
			//nolint:revive // we use our own version of the errors package.
			return errors.New(fmt.Sprintf("%s or %s should not be specified when %s is, as they are obsolete and misleading.", validatorIndex.String(), validatorPubkey.String(), all.String()))
		}

		err := eth2util.ValidateBeaconNodeHeaders(config.BeaconNodeHeaders)
		if err != nil {
			return err
		}

		config.ValidatorIndexPresent = valIdxPresent
		config.SkipBeaconNodeCheck = valIdxPresent && valPubkPresent

		return nil
	})

	return cmd
}

func runSignPartialExit(ctx context.Context, config exitConfig) error {
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

	rawValKeys, err := keystore.LoadFilesUnordered(config.ValidatorKeysDir)
	if err != nil {
		return errors.Wrap(err, "load keystore, check if path exists", z.Str("validator_keys_dir", config.ValidatorKeysDir))
	}

	valKeys, err := rawValKeys.SequencedKeys()
	if err != nil {
		return errors.Wrap(err, "load keystore")
	}

	shares, err := keystore.KeysharesToValidatorPubkey(cl, valKeys)
	if err != nil {
		return errors.Wrap(err, "match local validator key shares with their counterparty in cluster lock")
	}

	shareIdx, err := keystore.ShareIdxForCluster(cl, *identityKey.PubKey())
	if err != nil {
		return errors.Wrap(err, "determine operator index from cluster lock for supplied identity key")
	}

	oAPI, err := obolapi.New(config.PublishAddress, obolapi.WithTimeout(config.PublishTimeout))
	if err != nil {
		return errors.Wrap(err, "create Obol API client", z.Str("publish_address", config.PublishAddress))
	}

	beaconNodeHeaders, err := eth2util.ParseBeaconNodeHeaders(config.BeaconNodeHeaders)
	if err != nil {
		return err
	}

	eth2Cl, err := eth2Client(ctx, config.FallbackBeaconNodeAddrs, beaconNodeHeaders, config.BeaconNodeEndpoints, config.BeaconNodeTimeout, [4]byte(cl.GetForkVersion()))
	if err != nil {
		return errors.Wrap(err, "create eth2 client for specified beacon node(s)", z.Any("beacon_nodes_endpoints", config.BeaconNodeEndpoints))
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

	var exitBlobs []obolapi.ExitBlob
	if config.All {
		exitBlobs, err = signAllValidatorsExits(ctx, config, eth2Cl, shares)
		if err != nil {
			return errors.Wrap(err, "sign exits for all validators")
		}
	} else {
		exitBlobs, err = signSingleValidatorExit(ctx, config, eth2Cl, shares)
		if err != nil {
			return errors.Wrap(err, "sign exit for validator")
		}
	}

	if err := oAPI.PostPartialExits(ctx, cl.GetInitialMutationHash(), shareIdx, identityKey, exitBlobs...); err != nil {
		return errors.Wrap(err, "http POST partial exit message to Obol API")
	}

	return nil
}

func signSingleValidatorExit(ctx context.Context, config exitConfig, eth2Cl eth2wrap.Client, shares keystore.ValidatorShares) ([]obolapi.ExitBlob, error) {
	valEth2, err := fetchValidatorBLSPubKey(ctx, config, eth2Cl)
	if err != nil {
		return nil, errors.Wrap(err, "fetch validator public key")
	}

	validator := core.PubKeyFrom48Bytes(valEth2)

	ourShare, ok := shares[validator]
	if !ok {
		return nil, errors.New("validator not present in cluster lock", z.Str("validator", validator.String()))
	}

	valIndex, err := fetchValidatorIndex(ctx, config, eth2Cl)
	if err != nil {
		return nil, errors.Wrap(err, "fetch validator index")
	}

	log.Info(ctx, "Signing partial exit message for validator", z.Str("validator_public_key", valEth2.String()), z.U64("validator_index", uint64(valIndex)))

	exitMsg, err := signExit(ctx, eth2Cl, valIndex, ourShare.Share, eth2p0.Epoch(config.ExitEpoch))
	if err != nil {
		return nil, errors.Wrap(err, "sign partial exit message", z.Str("validator_public_key", valEth2.String()), z.U64("validator_index", uint64(valIndex)), z.Int("exit_epoch", int(config.ExitEpoch)))
	}

	return []obolapi.ExitBlob{
		{
			PublicKey:         valEth2.String(),
			SignedExitMessage: exitMsg,
		},
	}, nil
}

func signAllValidatorsExits(ctx context.Context, config exitConfig, eth2Cl eth2wrap.Client, shares keystore.ValidatorShares) ([]obolapi.ExitBlob, error) {
	var valsEth2 []eth2p0.BLSPubKey
	for pk := range shares {
		eth2PK, err := pk.ToETH2()
		if err != nil {
			return nil, errors.Wrap(err, "convert core pubkey to eth2 pubkey", z.Str("pub_key", eth2PK.String()))
		}
		valsEth2 = append(valsEth2, eth2PK)
	}

	rawValData, err := queryBeaconForValidator(ctx, eth2Cl, valsEth2, nil)
	if err != nil {
		return nil, errors.Wrap(err, "fetch all validators indices from beacon")
	}

	for _, val := range rawValData.Data {
		share, ok := shares[core.PubKeyFrom48Bytes(val.Validator.PublicKey)]
		if !ok {
			return nil, errors.New("validator public key not found in cluster lock", z.Str("validator_public_key", val.Validator.PublicKey.String()))
		}
		share.Index = int(val.Index)
		shares[core.PubKeyFrom48Bytes(val.Validator.PublicKey)] = share
	}

	log.Info(ctx, "Signing partial exit message for all active validators")

	var exitBlobs []obolapi.ExitBlob
	for pk, share := range shares {
		exitMsg, err := signExit(ctx, eth2Cl, eth2p0.ValidatorIndex(share.Index), share.Share, eth2p0.Epoch(config.ExitEpoch))
		if err != nil {
			return nil, errors.Wrap(err, "sign partial exit message", z.Str("validator_public_key", pk.String()), z.Int("validator_index", share.Index), z.Int("exit_epoch", int(config.ExitEpoch)))
		}
		eth2PK, err := pk.ToETH2()
		if err != nil {
			return nil, errors.Wrap(err, "convert core pubkey to eth2 pubkey", z.Str("core_pubkey", pk.String()))
		}
		exitBlob := obolapi.ExitBlob{
			PublicKey:         eth2PK.String(),
			SignedExitMessage: exitMsg,
		}
		exitBlobs = append(exitBlobs, exitBlob)
		log.Info(ctx, "Successfully signed exit message", z.Str("validator_public_key", pk.String()), z.Int("validator_index", share.Index))
	}

	return exitBlobs, nil
}

func fetchValidatorBLSPubKey(ctx context.Context, config exitConfig, eth2Cl eth2wrap.Client) (eth2p0.BLSPubKey, error) {
	if config.ValidatorPubkey != "" {
		valEth2, err := core.PubKey(config.ValidatorPubkey).ToETH2()
		if err != nil {
			return eth2p0.BLSPubKey{}, errors.Wrap(err, "convert core pubkey to eth2 pubkey", z.Str("core_pubkey", config.ValidatorPubkey))
		}

		return valEth2, nil
	}

	rawValData, err := queryBeaconForValidator(ctx, eth2Cl, nil, []eth2p0.ValidatorIndex{eth2p0.ValidatorIndex(config.ValidatorIndex)})
	if err != nil {
		return eth2p0.BLSPubKey{}, errors.Wrap(err, "fetch validator pubkey from beacon", z.Str("beacon_address", eth2Cl.Address()), z.U64("validator_index", config.ValidatorIndex))
	}

	for _, val := range rawValData.Data {
		if val.Index == eth2p0.ValidatorIndex(config.ValidatorIndex) {
			return val.Validator.PublicKey, nil
		}
	}

	return eth2p0.BLSPubKey{}, errors.New("validator index not found in beacon node response", z.Str("beacon_address", eth2Cl.Address()), z.U64("validator_index", config.ValidatorIndex), z.Any("raw_response", rawValData))
}

func fetchValidatorIndex(ctx context.Context, config exitConfig, eth2Cl eth2wrap.Client) (eth2p0.ValidatorIndex, error) {
	if config.ValidatorIndexPresent {
		return eth2p0.ValidatorIndex(config.ValidatorIndex), nil
	}

	valEth2, err := core.PubKey(config.ValidatorPubkey).ToETH2()
	if err != nil {
		return 0, errors.Wrap(err, "convert core pubkey to eth2 pubkey", z.Str("core_pubkey", config.ValidatorPubkey))
	}

	rawValData, err := queryBeaconForValidator(ctx, eth2Cl, []eth2p0.BLSPubKey{valEth2}, nil)
	if err != nil {
		return 0, errors.Wrap(err, "fetch validator index from beacon", z.Str("beacon_address", eth2Cl.Address()), z.Str("validator_pubkey", valEth2.String()))
	}

	for _, val := range rawValData.Data {
		if val.Validator.PublicKey == valEth2 {
			return val.Index, nil
		}
	}

	return 0, errors.New("validator public key not found in beacon node response", z.Str("beacon_address", eth2Cl.Address()), z.Str("validator_pubkey", valEth2.String()), z.Any("raw_response", rawValData))
}

func queryBeaconForValidator(ctx context.Context, eth2Cl eth2wrap.Client, pubKeys []eth2p0.BLSPubKey, indices []eth2p0.ValidatorIndex) (*eth2api.Response[map[eth2p0.ValidatorIndex]*eth2v1.Validator], error) {
	valAPICallOpts := &eth2api.ValidatorsOpts{
		State:   "head",
		PubKeys: pubKeys,
		Indices: indices,
	}

	rawValData, err := eth2Cl.Validators(ctx, valAPICallOpts)
	if err != nil {
		return nil, errors.Wrap(err, "fetch validators from beacon", z.Str("beacon_address", eth2Cl.Address()), z.Any("options", valAPICallOpts))
	}

	return rawValData, nil
}
