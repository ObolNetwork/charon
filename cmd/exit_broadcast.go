// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
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

		return nil
	})

	return cmd
}

func runBcastFullExit(ctx context.Context, config exitConfig) error {
	identityKey, err := k1util.Load(config.PrivateKeyPath)
	if err != nil {
		return errors.Wrap(err, "could not load identity key")
	}

	cl, err := loadClusterManifest("", config.LockFilePath)
	if err != nil {
		return errors.Wrap(err, "could not load cluster-lock.json")
	}

	eth2Cl, err := eth2Client(ctx, config.BeaconNodeEndpoints, config.BeaconNodeTimeout, [4]byte(cl.GetForkVersion()))
	if err != nil {
		return errors.Wrap(err, "cannot create eth2 client for specified beacon node")
	}

	fullExits := make(map[core.PubKey]eth2p0.SignedVoluntaryExit)
	// multiple
	if config.All {
		if config.ExitFromFileDir != "" {
			entries, err := os.ReadDir(config.ExitFromFileDir)
			if err != nil {
				return errors.Wrap(err, "could not read exits directory")
			}
			for _, entry := range entries {
				if !strings.HasPrefix(entry.Name(), "exit-") {
					continue
				}
				exit, err := fetchFullExit(ctx, path.Join(config.ExitFromFileDir+"/"+entry.Name()), config, cl, identityKey, "")
				if err != nil {
					return errors.Wrap(err, "fetch full exit for all from dir")
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
				exit, err := fetchFullExit(ctx, "", config, cl, identityKey, validatorPubKeyHex)
				if err != nil {
					return errors.Wrap(err, "fetch full exit for all from public key")
				}
				validatorPubKey, err := core.PubKeyFromBytes(validator.GetPublicKey())
				if err != nil {
					return errors.Wrap(err, "convert public key for validator")
				}
				fullExits[validatorPubKey] = exit
			}
		}
	} else {
		exit, err := fetchFullExit(ctx, strings.TrimSpace(config.ExitFromFilePath), config, cl, identityKey, config.ValidatorPubkey)
		if err != nil {
			return errors.Wrap(err, "fetch full exit for public key")
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
		return "", errors.Wrap(err, "cannot decode public key hex from file name")
	}
	validatorPubKey, err := core.PubKeyFromBytes(validatorPubKeyBytes)
	if err != nil {
		return "", errors.Wrap(err, "cannot decode core public key from hex")
	}

	return validatorPubKey, nil
}

func fetchFullExit(ctx context.Context, exitFilePath string, config exitConfig, cl *manifestpb.Cluster, identityKey *k1.PrivateKey, validatorPubKey string) (eth2p0.SignedVoluntaryExit, error) {
	var fullExit eth2p0.SignedVoluntaryExit
	var err error

	if len(exitFilePath) != 0 {
		log.Info(ctx, "Retrieving full exit message from path", z.Str("path", exitFilePath))
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
			return errors.Wrap(err, "could not serialize validator key bytes")
		}

		pubkey, err := tblsconv.PubkeyFromBytes(rawPkBytes)
		if err != nil {
			return errors.Wrap(err, "could not convert validator key bytes to BLS public key")
		}

		// parse signature
		signature, err := tblsconv.SignatureFromBytes(fullExit.Signature[:])
		if err != nil {
			return errors.Wrap(err, "could not parse BLS signature from bytes")
		}

		exitRoot, err := sigDataForExit(
			valCtx,
			*fullExit.Message,
			eth2Cl,
			fullExit.Message.Epoch,
		)
		if err != nil {
			return errors.Wrap(err, "cannot calculate hash tree root for exit message for verification")
		}

		if err := tbls.Verify(pubkey, exitRoot[:], signature); err != nil {
			return errors.Wrap(err, "exit message signature not verified")
		}
	}

	for validator, fullExit := range exits {
		valCtx := log.WithCtx(ctx, z.Str("validator", validator.String()))
		if err := eth2Cl.SubmitVoluntaryExit(valCtx, &fullExit); err != nil {
			return errors.Wrap(err, "could not submit voluntary exit")
		}
	}

	return nil
}

// exitFromObolAPI fetches an eth2p0.SignedVoluntaryExit message from publishAddr for the given validatorPubkey.
func exitFromObolAPI(ctx context.Context, validatorPubkey, publishAddr string, publishTimeout time.Duration, cl *manifestpb.Cluster, identityKey *k1.PrivateKey) (eth2p0.SignedVoluntaryExit, error) {
	oAPI, err := obolapi.New(publishAddr, obolapi.WithTimeout(publishTimeout))
	if err != nil {
		return eth2p0.SignedVoluntaryExit{}, errors.Wrap(err, "could not create obol api client")
	}

	shareIdx, err := keystore.ShareIdxForCluster(cl, *identityKey.PubKey())
	if err != nil {
		return eth2p0.SignedVoluntaryExit{}, errors.Wrap(err, "could not determine operator index from cluster lock for supplied identity key")
	}

	fullExit, err := oAPI.GetFullExit(ctx, validatorPubkey, cl.GetInitialMutationHash(), shareIdx, identityKey)
	if err != nil {
		return eth2p0.SignedVoluntaryExit{}, errors.Wrap(err, "could not load full exit data from Obol API")
	}

	return fullExit.SignedExitMessage, nil
}

// exitFromPath loads an eth2p0.SignedVoluntaryExit from path.
func exitFromPath(path string) (eth2p0.SignedVoluntaryExit, error) {
	f, err := os.Open(path)
	if err != nil {
		return eth2p0.SignedVoluntaryExit{}, errors.Wrap(err, "can't open signed exit message from path")
	}

	var exit eth2p0.SignedVoluntaryExit

	if err := json.NewDecoder(f).Decode(&exit); err != nil {
		return eth2p0.SignedVoluntaryExit{}, errors.Wrap(err, "invalid signed exit message")
	}

	return exit, nil
}
