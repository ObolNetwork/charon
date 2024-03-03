// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"fmt"
	"path/filepath"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	libp2plog "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

func newListActiveValidatorsCmd(runFunc func(context.Context, exitConfig) error) *cobra.Command {
	var config exitConfig

	cmd := &cobra.Command{
		Use:   "active-validator-list",
		Short: "List all active validators",
		Long:  `Returns a list of all the DV in the specified cluster whose status is ACTIVE_ONGOING, i.e. can be exited.`,
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

	cmd.Flags().BoolVar(&config.PlaintextOutput, "plaintext", false, "Prints each active validator on a line, without any debugging or logging artifact. Useful for scripting.")

	bindGenericExitFlags(cmd, &config)
	bindLogFlags(cmd.Flags(), &config.Log)

	return cmd
}

func runListActiveValidatorsCmd(ctx context.Context, config exitConfig) error {
	valList, err := listActiveVals(ctx, config)
	if err != nil {
		return err
	}

	for _, validator := range valList {
		if config.PlaintextOutput {
			//nolint:forbidigo // used for plaintext printing
			fmt.Println(validator)
			continue
		}

		log.Info(ctx, "Validator", z.Str("pubkey", validator))
	}

	return nil
}

func listActiveVals(ctx context.Context, config exitConfig) ([]string, error) {
	lockFilePath := filepath.Join(config.DataDir, "cluster-lock.json")
	manifestFilePath := filepath.Join(config.DataDir, "cluster-manifest.pb")

	cl, err := loadClusterManifest(manifestFilePath, lockFilePath)
	if err != nil {
		return nil, errors.Wrap(err, "could not load cluster data")
	}

	eth2Cl, err := eth2Client(ctx, config.BeaconNodeURL)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create eth2 client for specified beacon node")
	}

	var allVals []eth2p0.BLSPubKey

	for _, v := range cl.Validators {
		allVals = append(allVals, eth2p0.BLSPubKey(v.PublicKey))
	}

	valData, err := eth2Cl.Validators(ctx, &eth2api.ValidatorsOpts{
		PubKeys: allVals,
		State:   "head",
	})
	if err != nil {
		return nil, errors.Wrap(err, "cannot fetch validator list")
	}

	var ret []string

	for _, validator := range valData.Data {
		if validator.Status == eth2v1.ValidatorStateActiveOngoing {
			valStr := validator.Validator.PublicKey.String()
			ret = append(ret, valStr)
		}
	}

	return ret, nil
}
