// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/json"
	"os"
	"strings"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	libp2plog "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
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
		Short: "Submit partial exit message for a distributed validator.",
		Long:  `Retrieves and broadcasts a fully signed validator exit message, aggregated with the available partial signatures retrieved from the publish-address.`,
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
		{validatorPubkey, true},
		{beaconNodeURL, true},
		{exitFromFile, false},
	})

	bindLogFlags(cmd.Flags(), &config.Log)

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

	validator := core.PubKey(config.ValidatorPubkey)
	if _, err := validator.Bytes(); err != nil {
		return errors.Wrap(err, "cannot convert validator pubkey to bytes")
	}

	ctx = log.WithCtx(ctx, z.Str("validator", validator.String()))

	eth2Cl, err := eth2Client(ctx, config.BeaconNodeURL)
	if err != nil {
		return errors.Wrap(err, "cannot create eth2 client for specified beacon node")
	}

	var fullExit eth2p0.SignedVoluntaryExit
	maybeExitFilePath := strings.TrimSpace(config.ExitFromFilePath)

	if len(maybeExitFilePath) != 0 {
		log.Info(ctx, "Retrieving full exit message from path", z.Str("path", maybeExitFilePath))
		fullExit, err = exitFromPath(maybeExitFilePath)
	} else {
		log.Info(ctx, "Retrieving full exit message from publish address")
		fullExit, err = exitFromObolAPI(ctx, config.ValidatorPubkey, config.PublishAddress, cl, identityKey)
	}

	if err != nil {
		return err
	}

	// parse validator public key
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
		ctx,
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

	if err := eth2Cl.SubmitVoluntaryExit(ctx, &fullExit); err != nil {
		return errors.Wrap(err, "could not submit voluntary exit")
	}

	return nil
}

// exitFromObolAPI fetches an eth2p0.SignedVoluntaryExit message from publishAddr for the given validatorPubkey.
func exitFromObolAPI(ctx context.Context, validatorPubkey, publishAddr string, cl *manifestpb.Cluster, identityKey *k1.PrivateKey) (eth2p0.SignedVoluntaryExit, error) {
	oAPI, err := obolapi.New(publishAddr)
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
