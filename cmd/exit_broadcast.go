// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	libp2plog "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/app/z"
	manifestpb "github.com/obolnetwork/charon/cluster/manifestpb/v1"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

func newBcastFullExitCmd(runFunc func(context.Context, exitConfig) error) *cobra.Command {
	var config exitConfig

	cmd := &cobra.Command{
		Use:   "broadcast",
		Short: "Submit partial exit message for a distributed validator",
		Long:  `Retrieves and broadcasts to the configured beacon node a fully signed validator exit message, aggregated with the available partial signatures retrieved from the publish-address. Can also read a signed exit message from disk, in order to be broadcasted to the configured beacon node.`,
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
		{beaconNodeEndpoints, true},
		{exitFromFile, false},
		{exitFromDir, false},
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
		valPubkPresent := cmd.Flags().Lookup(validatorPubkey.String()).Changed
		exitFilePresent := cmd.Flags().Lookup(exitFromFile.String()).Changed
		exitDirPresent := cmd.Flags().Lookup(exitFromDir.String()).Changed

		if !valPubkPresent && !config.All {
			//nolint:revive,perfsprint // we use our own version of the errors package; keep consistency with other checks.
			return errors.New(fmt.Sprintf("%s must be specified when exiting single validator.", validatorPubkey.String()))
		}

		if config.All && valPubkPresent {
			//nolint:revive // we use our own version of the errors package.
			return errors.New(fmt.Sprintf("%s should not be specified when %s is, as it is obsolete and misleading.", validatorPubkey.String(), all.String()))
		}

		if valPubkPresent && exitDirPresent {
			//nolint:revive // we use our own version of the errors package.
			return errors.New(fmt.Sprintf("if you want to specify exit file for single validator, you must provide %s and not %s.", exitFromFile.String(), exitFromDir.String()))
		}

		if config.All && exitFilePresent {
			//nolint:revive // we use our own version of the errors package.
			return errors.New(fmt.Sprintf("if you want to specify exit file directory for all validators, you must provide %s and not %s.", exitFromDir.String(), exitFromFile.String()))
		}

		err := eth2util.ValidateHTTPHeaders(config.BeaconNodeHeaders)
		if err != nil {
			return err
		}

		return nil
	})

	return cmd
}

func runBcastFullExit(ctx context.Context, config exitConfig) error {
	// Check if custom testnet configuration is provided.
	if config.testnetConfig.IsNonZero() {
		// Add testnet config to supported networks.
		eth2util.AddTestNetwork(config.testnetConfig)
	}

	identityKey, err := k1util.Load(config.PrivateKeyPath)
	if err != nil {
		return errors.Wrap(err, "load identity key")
	}

	cl, err := loadClusterLock(config.LockFilePath)
	if err != nil {
		return err
	}

	beaconNodeHeaders, err := eth2util.ParseHTTPHeaders(config.BeaconNodeHeaders)
	if err != nil {
		return err
	}

	eth2Cl, err := eth2Client(ctx, config.FallbackBeaconNodeAddrs, beaconNodeHeaders, config.BeaconNodeEndpoints, config.BeaconNodeTimeout, [4]byte(cl.GetForkVersion()))
	if err != nil {
		return errors.Wrap(err, "create eth2 client for specified beacon node(s)", z.Any("beacon_nodes_endpoints", config.BeaconNodeEndpoints))
	}

	fullExits := make(map[core.PubKey]eth2p0.SignedVoluntaryExit)

	if config.All {
		if config.ExitFromFileDir != "" {
			entries, err := os.ReadDir(config.ExitFromFileDir)
			if err != nil {
				return errors.Wrap(err, "read exits directory", z.Str("exit_file_dir", config.ExitFromFileDir))
			}

			for _, entry := range entries {
				if !strings.HasPrefix(entry.Name(), "exit-") {
					continue
				}

				valCtx := log.WithCtx(ctx, z.Str("validator_exit_file", entry.Name()))

				exit, err := fetchFullExit(valCtx, filepath.Join(config.ExitFromFileDir, entry.Name()), config, cl, identityKey, "")
				if err != nil {
					return err
				}

				validatorPubKey, err := validatorPubKeyFromFileName(entry.Name())
				if err != nil {
					return err
				}

				fullExits[validatorPubKey] = exit
			}
		} else {
			for _, validator := range cl.GetValidators() {
				validatorPubKeyHex := fmt.Sprintf("0x%x", validator.GetPublicKey())

				valCtx := log.WithCtx(ctx, z.Str("validator_public_key", validatorPubKeyHex))

				exit, err := fetchFullExit(valCtx, "", config, cl, identityKey, validatorPubKeyHex)
				if err != nil {
					if errors.Is(err, obolapi.ErrNoExit) {
						log.Warn(ctx, fmt.Sprintf("full exit data from Obol API for validator %v not available (validator may not be activated)", validatorPubKeyHex), nil)
						continue
					}

					return errors.Wrap(err, "fetch full exit for all validators from public key")
				}

				validatorPubKey, err := core.PubKeyFromBytes(validator.GetPublicKey())
				if err != nil {
					return errors.Wrap(err, "convert public key for validator")
				}

				fullExits[validatorPubKey] = exit
			}
		}
	} else {
		valCtx := log.WithCtx(ctx, z.Str("validator_public_key", config.ValidatorPubkey), z.Str("validator_exit_file", config.ExitFromFilePath))

		exit, err := fetchFullExit(valCtx, strings.TrimSpace(config.ExitFromFilePath), config, cl, identityKey, config.ValidatorPubkey)
		if err != nil {
			return errors.Wrap(err, "fetch full exit for validator", z.Str("validator_public_key", config.ValidatorPubkey), z.Str("validator_exit_file", config.ExitFromFilePath))
		}

		var validatorPubKey core.PubKey
		if len(strings.TrimSpace(config.ExitFromFilePath)) != 0 {
			validatorPubKey, err = validatorPubKeyFromFileName(config.ExitFromFilePath)
			if err != nil {
				return err
			}
		} else {
			validatorPubKey = core.PubKey(config.ValidatorPubkey)
		}

		fullExits[validatorPubKey] = exit
	}

	return broadcastExitsToBeacon(ctx, eth2Cl, fullExits)
}

func validatorPubKeyFromFileName(fileName string) (core.PubKey, error) {
	fileNameChecked := filepath.Base(fileName)
	fileExtension := filepath.Ext(fileNameChecked)
	validatorPubKeyHex := strings.TrimPrefix(strings.TrimSuffix(fileNameChecked, fileExtension), "exit-0x")

	validatorPubKeyBytes, err := hex.DecodeString(validatorPubKeyHex)
	if err != nil {
		return "", errors.Wrap(err, "decode public key hex from file name", z.Str("public_key", validatorPubKeyHex))
	}

	validatorPubKey, err := core.PubKeyFromBytes(validatorPubKeyBytes)
	if err != nil {
		return "", errors.Wrap(err, "decode core public key from hex")
	}

	return validatorPubKey, nil
}

func fetchFullExit(ctx context.Context, exitFilePath string, config exitConfig, cl *manifestpb.Cluster, identityKey *k1.PrivateKey, validatorPubKey string) (eth2p0.SignedVoluntaryExit, error) {
	var (
		fullExit eth2p0.SignedVoluntaryExit
		err      error
	)

	if len(exitFilePath) != 0 {
		log.Info(ctx, "Retrieving full exit message from path")

		fullExit, err = exitFromPath(exitFilePath)
	} else {
		log.Info(ctx, "Retrieving full exit message from publish address")
		fullExit, err = exitFromObolAPI(ctx, validatorPubKey, config.PublishAddress, config.PublishTimeout, cl, identityKey)
	}

	return fullExit, err
}

func broadcastExitsToBeacon(ctx context.Context, eth2Cl eth2wrap.Client, exits map[core.PubKey]eth2p0.SignedVoluntaryExit) error {
	for validator, fullExit := range exits {
		valCtx := log.WithCtx(ctx, z.Str("validator", validator.String()))

		rawPkBytes, err := validator.Bytes()
		if err != nil {
			return errors.Wrap(err, "serialize validator key bytes", z.Str("validator", validator.String()))
		}

		pubkey, err := tblsconv.PubkeyFromBytes(rawPkBytes)
		if err != nil {
			return errors.Wrap(err, "convert validator key bytes to BLS public key")
		}

		// parse signature
		signature, err := tblsconv.SignatureFromBytes(fullExit.Signature[:])
		if err != nil {
			return errors.Wrap(err, "parse BLS signature from bytes", z.Str("exit_signature", fullExit.Signature.String()))
		}

		exitRoot, err := sigDataForExit(
			valCtx,
			*fullExit.Message,
			eth2Cl,
			fullExit.Message.Epoch,
		)
		if err != nil {
			return errors.Wrap(err, "calculate hash tree root for exit message for verification")
		}

		if err := tbls.Verify(pubkey, exitRoot[:], signature); err != nil {
			return errors.Wrap(err, "exit message signature not verified")
		}
	}

	for validator, fullExit := range exits {
		valCtx := log.WithCtx(ctx, z.Str("validator", validator.String()))
		if err := eth2Cl.SubmitVoluntaryExit(valCtx, &fullExit); err != nil {
			return errors.Wrap(err, "submit voluntary exit")
		}

		log.Info(valCtx, "Successfully submitted voluntary exit for validator")
	}

	return nil
}

// exitFromObolAPI fetches an eth2p0.SignedVoluntaryExit message from publishAddr for the given validatorPubkey.
func exitFromObolAPI(ctx context.Context, validatorPubkey, publishAddr string, publishTimeout time.Duration, cl *manifestpb.Cluster, identityKey *k1.PrivateKey) (eth2p0.SignedVoluntaryExit, error) {
	oAPI, err := obolapi.New(publishAddr, obolapi.WithTimeout(publishTimeout))
	if err != nil {
		return eth2p0.SignedVoluntaryExit{}, errors.Wrap(err, "create Obol API client", z.Str("publish_address", publishAddr))
	}

	shareIdx, err := keystore.ShareIdxForCluster(cl, *identityKey.PubKey())
	if err != nil {
		return eth2p0.SignedVoluntaryExit{}, errors.Wrap(err, "determine operator index from cluster lock for supplied identity key")
	}

	fullExit, err := oAPI.GetFullExit(ctx, validatorPubkey, cl.GetInitialMutationHash(), shareIdx, identityKey)
	if err != nil {
		return eth2p0.SignedVoluntaryExit{}, errors.Wrap(err, "load full exit data from Obol API", z.Str("publish_address", publishAddr))
	}

	return fullExit.SignedExitMessage, nil
}

// exitFromPath loads an eth2p0.SignedVoluntaryExit from path.
func exitFromPath(path string) (eth2p0.SignedVoluntaryExit, error) {
	f, err := os.Open(path)
	if err != nil {
		return eth2p0.SignedVoluntaryExit{}, errors.Wrap(err, "open signed exit message from path")
	}

	var exit eth2p0.SignedVoluntaryExit

	if err := json.NewDecoder(f).Decode(&exit); err != nil {
		return eth2p0.SignedVoluntaryExit{}, errors.Wrap(err, "invalid signed exit message")
	}

	return exit, nil
}
