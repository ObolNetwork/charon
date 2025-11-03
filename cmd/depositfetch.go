// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"os"
	"strings"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/deposit"
)

type depositFetchConfig struct {
	depositConfig

	DepositDataDir string
}

const defaultDepositDataDir = ".charon/deposit-data-<TIMESTAMP>"

func newDepositFetchCmd(runFunc func(context.Context, depositFetchConfig) error) *cobra.Command {
	var config depositFetchConfig

	cmd := &cobra.Command{
		Use:   "fetch",
		Short: "Fetch a full deposit message.",
		Long:  "Fetch full validator deposit messages using a remote API.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFunc(cmd.Context(), config)
		},
	}

	bindDepositFlags(cmd, &config.depositConfig)
	bindDepositFetchFlags(cmd, &config)

	wrapPreRunE(cmd, func(cmd *cobra.Command, _ []string) error {
		mustMarkFlagRequired(cmd, "validator-public-keys")
		return nil
	})

	return cmd
}

func bindDepositFetchFlags(cmd *cobra.Command, config *depositFetchConfig) {
	cmd.Flags().StringVar(&config.DepositDataDir, "deposit-data-dir", defaultDepositDataDir, "Path to the directory in which fetched deposit data will be stored.")
}

func runDepositFetch(ctx context.Context, config depositFetchConfig) error {
	cl, err := loadClusterLock(config.LockFilePath)
	if err != nil {
		return err
	}

	oAPI, err := obolapi.New(config.PublishAddress, obolapi.WithTimeout(config.PublishTimeout))
	if err != nil {
		return errors.Wrap(err, "create Obol API client", z.Str("publish_address", config.PublishAddress))
	}

	depositDatas := map[eth2p0.Gwei][]eth2p0.DepositData{}

	for _, pubkey := range config.ValidatorPublicKeys {
		log.Info(ctx, "Fetching full deposit message", z.Str("validator_pubkey", pubkey))

		dd, err := oAPI.GetFullDeposit(ctx, pubkey, cl.GetInitialMutationHash(), int(cl.GetThreshold()))
		if err != nil {
			return errors.Wrap(err, "fetch full deposit data from Obol API")
		}

		for _, d := range dd {
			log.Info(ctx, "Fetched full deposit message", z.Str("validator_pubkey", pubkey), z.U64("amount", uint64(d.Amount)))
			depositDatas[d.Amount] = append(depositDatas[d.Amount], d)
		}
	}

	var path string
	if config.DepositDataDir == defaultDepositDataDir {
		path = strings.Replace(config.DepositDataDir, "<TIMESTAMP>", time.Now().Format(time.RFC3339), 1)
	} else {
		path = config.DepositDataDir
	}

	err = os.MkdirAll(path, 0o755)
	if err != nil && !os.IsExist(err) {
		return errors.Wrap(err, "create deposit data dir")
	}

	network, err := eth2util.ForkVersionToNetwork(cl.GetForkVersion())
	if err != nil {
		return err
	}

	for _, depositDatas := range depositDatas {
		err = deposit.WriteDepositDataFile(depositDatas, network, path)
		if err != nil {
			return err
		}
	}

	return nil
}
