// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"path/filepath"

	libp2plog "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

func newBcastFullExitCmd(runFunc func(context.Context, exitConfig) error) *cobra.Command {
	var config exitConfig

	cmd := &cobra.Command{
		Use:   "broadcast",
		Short: "Broadcast exit",
		Long:  `Broadcasts a full exit message, aggregated with the available partial signatures retrieved from Obol API.`,
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

func runBcastFullExit(ctx context.Context, config exitConfig) error {
	lockFilePath := filepath.Join(config.DataDir, "cluster-lock.json")
	manifestFilePath := filepath.Join(config.DataDir, "cluster-manifest.pb")
	identityKeyPath := filepath.Join(config.DataDir, "charon-enr-private-key")

	identityKey, err := k1util.Load(identityKeyPath)
	if err != nil {
		return errors.Wrap(err, "could not load identity key")
	}

	cl, err := loadClusterManifest(manifestFilePath, lockFilePath)
	if err != nil {
		return errors.Wrap(err, "could not load cluster data")
	}

	validator := core.PubKey(config.ValidatorAddr)
	if _, err := validator.Bytes(); err != nil {
		return errors.Wrap(err, "cannot convert validator pubkey to bytes")
	}

	ctx = log.WithCtx(ctx, z.Str("validator", validator.String()))

	eth2Cl, err := eth2Client(ctx, config.BeaconNodeURL)
	if err != nil {
		return errors.Wrap(err, "cannot create eth2 client for specified beacon node")
	}

	oAPI, err := obolapi.New(config.ObolAPIEndpoint)
	if err != nil {
		return errors.Wrap(err, "could not create obol api client")
	}

	log.Info(ctx, "Retrieving full exit message")

	shareIdx, err := keystore.ShareIdxForCluster(cl, *identityKey.PubKey())
	if err != nil {
		return errors.Wrap(err, "could not load share index from cluster lock")
	}

	fullExit, err := oAPI.GetFullExit(ctx, config.ValidatorAddr, cl.GetInitialMutationHash(), shareIdx, identityKey)
	if err != nil {
		return errors.Wrap(err, "could not load full exit data from Obol API")
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
	signature, err := tblsconv.SignatureFromBytes(fullExit.SignedExitMessage.Signature[:])
	if err != nil {
		return errors.Wrap(err, "could not parse BLS signature from bytes")
	}

	exitRoot, err := sigDataForExit(
		ctx,
		*fullExit.SignedExitMessage.Message,
		eth2Cl,
		fullExit.SignedExitMessage.Message.Epoch,
	)
	if err != nil {
		return errors.Wrap(err, "cannot calculate hash tree root for exit message for verification")
	}

	if err := tbls.Verify(pubkey, exitRoot[:], signature); err != nil {
		return errors.Wrap(err, "exit message signature not verified")
	}

	if err := eth2Cl.SubmitVoluntaryExit(ctx, &fullExit.SignedExitMessage); err != nil {
		return errors.Wrap(err, "could submit voluntary exit")
	}

	return nil
}
