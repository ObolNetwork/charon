// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"context"
	crand "crypto/rand"
	"encoding/json"
	"os"
	"path"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/p2p"
)

type createDKGConfig struct {
	OutputDir         string
	Name              string
	NumValidators     int
	Threshold         int
	FeeRecipient      string
	WithdrawalAddress string
	Network           string
	DKGAlgo           string
	OperatorENRs      []string
}

// networkToForkVersion maps an ethereum network name (ex: "goerli") to the corresponding fork version (ex: "0x00001020").
// Note that the fork versions are added in increasing order.
var networkToForkVersion = map[string]string{
	"mainnet": "0x00000000",
	"gnosis":  "0x00000064",
	"goerli":  "0x00001020",
	"kiln":    "0x70000069",
	"ropsten": "0x80000069",
	"sepolia": "0x90000069",
}

func newCreateDKGCmd(runFunc func(context.Context, createDKGConfig) error) *cobra.Command {
	var config createDKGConfig

	cmd := &cobra.Command{
		Use:   "dkg",
		Short: "Create the configuration for a new Distributed Key Generation ceremony using charon dkg",
		Long:  `Create a cluster definition file that will be used by all participants of a DKG.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFunc(cmd.Context(), config)
		},
	}

	bindCreateDKGFlags(cmd, &config)

	return cmd
}

func bindCreateDKGFlags(cmd *cobra.Command, config *createDKGConfig) {
	const operatorENRs = "operator-enrs"

	cmd.Flags().StringVar(&config.Name, "name", "", "Optional cosmetic cluster name")
	cmd.Flags().StringVar(&config.OutputDir, "output-dir", ".charon", "The folder to write the output cluster-definition.json file to.")
	cmd.Flags().IntVar(&config.NumValidators, "num-validators", 1, "The number of distributed validators the cluster will manage (32ETH staked for each).")
	cmd.Flags().IntVarP(&config.Threshold, "threshold", "t", 0, "Optional override of threshold required for signature reconstruction. Defaults to ceil(n*2/3) if zero. Warning, non-default values decrease security.")
	cmd.Flags().StringVar(&config.FeeRecipient, "fee-recipient-address", "", "Optional Ethereum address of the fee recipient")
	cmd.Flags().StringVar(&config.WithdrawalAddress, "withdrawal-address", defaultWithdrawalAddr, "Withdrawal Ethereum address")
	cmd.Flags().StringVar(&config.Network, "network", defaultNetwork, "Ethereum network to create validators for. Options: mainnet, gnosis, goerli, kiln, ropsten, sepolia.")
	cmd.Flags().StringVar(&config.DKGAlgo, "dkg-algorithm", "default", "DKG algorithm to use; default, keycast, frost")
	cmd.Flags().StringSliceVar(&config.OperatorENRs, operatorENRs, nil, "[REQUIRED] Comma-separated list of each operator's Charon ENR address.")

	mustMarkFlagRequired(cmd, operatorENRs)
}

func mustMarkFlagRequired(cmd *cobra.Command, flag string) {
	if err := cmd.MarkFlagRequired(flag); err != nil {
		panic(err) // Panic is ok since this is unexpected and covered by unit tests.
	}
}

func runCreateDKG(ctx context.Context, conf createDKGConfig) (err error) {
	defer func() {
		if err != nil {
			log.Error(ctx, "Fatal run error", err)
		}
	}()

	if _, err := os.Stat(path.Join(conf.OutputDir, "cluster-definition.json")); err == nil {
		return errors.New("existing cluster-definition.json found. Try again after deleting it")
	}

	// Don't allow cluster size to be less than 4.
	if len(conf.OperatorENRs) < minNodes {
		return errors.New("insufficient operator ENRs (min = 4)")
	}

	var operators []cluster.Operator
	for i, opENR := range conf.OperatorENRs {
		_, err := p2p.DecodeENR(opENR)
		if err != nil {
			return errors.Wrap(err, "invalid ENR", z.Int("operator", i))
		}
		operators = append(operators, cluster.Operator{
			ENR: opENR,
		})
	}

	safeThreshold := cluster.Threshold(len(conf.OperatorENRs))
	if conf.Threshold == 0 {
		conf.Threshold = safeThreshold
	} else if conf.Threshold != safeThreshold {
		log.Warn(ctx, "Non standard `--threshold` flag provided, this will affect cluster safety", nil, z.Int("threshold", conf.Threshold), z.Int("safe_threshold", safeThreshold))
	}

	if !validNetworks[conf.Network] {
		return errors.New("unsupported network", z.Str("network", conf.Network))
	}

	if err := validateWithdrawalAddr(conf.WithdrawalAddress, conf.Network); err != nil {
		return err
	}

	forkVersion := networkToForkVersion[conf.Network]

	def, err := cluster.NewDefinition(conf.Name, conf.NumValidators, conf.Threshold, conf.FeeRecipient, conf.WithdrawalAddress,
		forkVersion, operators, crand.Reader)
	if err != nil {
		return err
	}

	def.DKGAlgorithm = conf.DKGAlgo

	if err := def.VerifySignatures(); err != nil {
		return err
	}

	b, err := json.MarshalIndent(def, "", " ")
	if err != nil {
		return errors.Wrap(err, "marshal definition")
	}

	// Best effort creation of output dir, but error when writing the file.
	_ = os.MkdirAll(conf.OutputDir, 0o755)

	if err := os.WriteFile(path.Join(conf.OutputDir, "cluster-definition.json"), b, 0o444); err != nil {
		return errors.Wrap(err, "write definition")
	}

	return nil
}

func validateWithdrawalAddr(addr string, network string) error {
	if !common.IsHexAddress(addr) {
		return errors.New("invalid address", z.Str("addr", addr))
	}

	// We cannot allow a zero withdrawal address on mainnet or gnosis.
	if (network == "mainnet" || network == "gnosis") &&
		addr == defaultWithdrawalAddr {
		return errors.New("zero address forbidden on this network", z.Str("network", network))
	}

	return nil
}
