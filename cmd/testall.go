// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"io"

	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
)

type testAllConfig struct {
	testConfig
	Peers       testPeersConfig
	Beacon      testBeaconConfig
	Validator   testValidatorConfig
	MEV         testMEVConfig
	Performance testPerformanceConfig
}

func newTestAllCmd(runFunc func(context.Context, io.Writer, testAllConfig) error) *cobra.Command {
	var config testAllConfig

	cmd := &cobra.Command{
		Use:   "all",
		Short: "Run tests towards peer nodes, beacon nodes, validator client, MEV relays, own hardware and internet connectivity.",
		Long:  `Run tests towards peer nodes, beacon nodes, validator client, MEV relays, own hardware and internet connectivity. Verify that Charon can efficiently do its duties on the tested setup.`,
		Args:  cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return mustOutputToFileOnQuiet(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFunc(cmd.Context(), cmd.OutOrStdout(), config)
		},
	}

	bindTestFlags(cmd, &config.testConfig)

	bindTestPeersFlags(cmd, &config.Peers, "peers-")
	bindTestBeaconFlags(cmd, &config.Beacon, "beacon-")
	bindTestValidatorFlags(cmd, &config.Validator, "validator-")
	bindTestMEVFlags(cmd, &config.MEV, "mev-")
	bindTestPerformanceFlags(cmd, &config.Performance, "performance-")

	bindP2PFlags(cmd, &config.Peers.P2P)
	bindDataDirFlag(cmd.Flags(), &config.Peers.DataDir)
	bindTestLogFlags(cmd.Flags(), &config.Peers.Log)

	wrapPreRunE(cmd, func(cmd *cobra.Command, _ []string) error {
		testCasesPresent := cmd.Flags().Lookup("test-cases").Changed

		if testCasesPresent {
			//nolint:revive // we use our own version of the errors package
			return errors.New("test-cases cannot be specified when explicitly running all test cases.")
		}

		return nil
	})

	return cmd
}

func runTestAll(ctx context.Context, w io.Writer, cfg testAllConfig) (err error) {
	cfg.Beacon.testConfig = cfg.testConfig
	err = runTestBeacon(ctx, w, cfg.Beacon)
	if err != nil {
		return err
	}

	cfg.Validator.testConfig = cfg.testConfig
	err = runTestValidator(ctx, w, cfg.Validator)
	if err != nil {
		return err
	}

	cfg.MEV.testConfig = cfg.testConfig
	err = runTestMEV(ctx, w, cfg.MEV)
	if err != nil {
		return err
	}

	cfg.Performance.testConfig = cfg.testConfig
	err = runTestPerformance(ctx, w, cfg.Performance)
	if err != nil {
		return err
	}

	cfg.Peers.testConfig = cfg.testConfig
	err = runTestPeers(ctx, w, cfg.Peers)
	if err != nil {
		return err
	}

	return nil
}
