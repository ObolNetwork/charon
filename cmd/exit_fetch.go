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
	"github.com/obolnetwork/charon/eth2util/keystore"
)

func newFetchExitCmd(runFunc func(context.Context, exitConfig) error) *cobra.Command {
	var config exitConfig

	cmd := &cobra.Command{
		Use:   "fetch",
		Short: "Fetch full exit from partial exit API instance.",
		Long:  `Fetch a full exit message for a given validator from the partial exit API instance.`,
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
		{validatorPubkey, true},
	})

	bindLogFlags(cmd.Flags(), &config.Log)

	return cmd
}

func runFetchExit(ctx context.Context, config exitConfig) error {
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
		return errors.Wrap(err, "could not load cluster data")
	}

	validator := core.PubKey(config.ValidatorPubkey)
	if _, err := validator.Bytes(); err != nil {
		return errors.Wrap(err, "cannot convert validator pubkey to bytes")
	}

	ctx = log.WithCtx(ctx, z.Str("validator", validator.String()))

	oAPI, err := obolapi.New(config.PublishAddress)
	if err != nil {
		return errors.Wrap(err, "could not create obol api client")
	}

	log.Info(ctx, "Retrieving full exit message")

	shareIdx, err := keystore.ShareIdxForCluster(cl, *identityKey.PubKey())
	if err != nil {
		return errors.Wrap(err, "could not load share index from cluster lock")
	}

	fullExit, err := oAPI.GetFullExit(ctx, config.ValidatorPubkey, cl.GetInitialMutationHash(), shareIdx, identityKey)
	if err != nil {
		return errors.Wrap(err, "could not load full exit data from Obol API")
	}

	fetchedExitFname := fmt.Sprintf("exit-%s.json", config.ValidatorPubkey)

	fetchedExitPath := filepath.Join(config.FetchedExitPath, fetchedExitFname)

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
