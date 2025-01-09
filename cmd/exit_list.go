// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"fmt"
	"regexp"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	libp2plog "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util"
)

func newListActiveValidatorsCmd(runFunc func(context.Context, exitConfig) error) *cobra.Command {
	var config exitConfig

	cmd := &cobra.Command{
		Use:   "active-validator-list",
		Short: "List all active validators",
		Long:  `Returns a list of all the DV in the specified cluster whose status is ACTIVE_ONGOING, i.e. can be exited.`,
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

	cmd.Flags().BoolVar(&config.PlaintextOutput, "plaintext", false, "Prints each active validator on a line, without any debugging or logging artifact. Useful for scripting.")

	bindExitFlags(cmd, &config, []exitCLIFlag{
		{lockFilePath, false},
		{beaconNodeEndpoints, true},
		{beaconNodeTimeout, false},
		{testnetName, false},
		{testnetForkVersion, false},
		{testnetChainID, false},
		{testnetGenesisTimestamp, false},
		{testnetCapellaHardFork, false},
		{beaconNodeHeaders, false},
	})

	bindLogFlags(cmd.Flags(), &config.Log)

	wrapPreRunE(cmd, func(cmd *cobra.Command, _ []string) error {
		if !regexp.MustCompile(`^([^=,]+)=([^=,]+)(,([^=,]+)=([^=,]+))*$`).MatchString(config.BeaconNodeHeaders) {
			return errors.New("beacon node headers must be comma separated values formatted as <header>=<value>")
		}
		return nil
	})

	return cmd
}

func runListActiveValidatorsCmd(ctx context.Context, config exitConfig) error {
	// Check if custom testnet configuration is provided.
	if config.testnetConfig.IsNonZero() {
		// Add testnet config to supported networks.
		eth2util.AddTestNetwork(config.testnetConfig)
	}

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

		log.Info(ctx, "Validator", z.Str("validator_public_key", validator))
	}

	return nil
}

func listActiveVals(ctx context.Context, config exitConfig) ([]string, error) {
	cl, err := loadClusterManifest("", config.LockFilePath)
	if err != nil {
		return nil, errors.Wrap(err, "load cluster lock", z.Str("lock_file_path", config.LockFilePath))
	}

	// Headers must be comma separated values of format <key>=<value>.
	// The pattern ([^=,]+) matches any string without '=' and ','.
	// Hence we are looking for a pair of <pattern>=<pattern> with optionally more pairs
	if !regexp.MustCompile(`^([^=,]+)=([^=,]+)(,([^=,]+)=([^=,]+))*$`).MatchString(config.BeaconNodeHeaders) {
		return nil, errors.New("beacon node headers must be comma separated values formatted as header=value")
	}

	pairs := regexp.MustCompile(`([^=,]+)=([^=,]+)`).FindAllStringSubmatch(config.BeaconNodeHeaders, -1)
	beaconNodeHeaders := make(map[string]string)
	for _, pair := range pairs {
		beaconNodeHeaders[pair[1]] = pair[2]
	}

	eth2Cl, err := eth2Client(ctx, beaconNodeHeaders, config.BeaconNodeEndpoints, config.BeaconNodeTimeout, [4]byte{}) // fine to avoid initializing a fork version, we're just querying the BN
	if err != nil {
		return nil, errors.Wrap(err, "create eth2 client for specified beacon node(s)", z.Any("beacon_nodes_endpoints", config.BeaconNodeEndpoints))
	}

	var allVals []eth2p0.BLSPubKey

	for _, v := range cl.GetValidators() {
		allVals = append(allVals, eth2p0.BLSPubKey(v.GetPublicKey()))
	}

	valData, err := eth2Cl.Validators(ctx, &eth2api.ValidatorsOpts{
		PubKeys: allVals,
		State:   "head",
	})
	if err != nil {
		return nil, errors.Wrap(err, "fetch validator list from beacon", z.Str("beacon_address", eth2Cl.Address()), z.Any("validators", allVals))
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
