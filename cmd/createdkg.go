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
	"github.com/spf13/pflag"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
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

var networkToForkVersion = map[string]string{
	"prater":   "0x00001020",
	"kintsugi": "0x60000069",
	"kiln":     "0x70000069",
	"gnosis":   "0x00000064",
	"mainnet":  "0x00000000",
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

	bindCreateDKGFlags(cmd.Flags(), &config)

	return cmd
}

func bindCreateDKGFlags(flags *pflag.FlagSet, config *createDKGConfig) {
	flags.StringVar(&config.Name, "name", "", "Optional cosmetic cluster name")
	flags.StringVar(&config.OutputDir, "output-dir", ".", "The folder to write the output cluster-definition.json file to.")
	flags.IntVar(&config.NumValidators, "num-validators", 1, "The number of distributed validators the cluster will manage (32ETH staked for each).")
	flags.IntVarP(&config.Threshold, "threshold", "t", 3, "The threshold required for signature reconstruction. Minimum is n-(ceil(n/3)-1).")
	flags.StringVar(&config.FeeRecipient, "fee-recipient-address", "", "Optional Ethereum address of the fee recipient")
	flags.StringVar(&config.WithdrawalAddress, "withdrawal-address", defaultWithdrawalAddr, "Withdrawal Ethereum address")
	flags.StringVar(&config.Network, "network", defaultNetwork, "Ethereum network to create validators for. Options: mainnet, prater, kintsugi, kiln, gnosis.")
	flags.StringVar(&config.DKGAlgo, "dkg-algorithm", "default", "DKG algorithm to use; default, keycast, frost")
	flags.StringSliceVar(&config.OperatorENRs, "operator-enrs", nil, "Comma-separated list of each operator's Charon ENR address")
}

func runCreateDKG(_ context.Context, conf createDKGConfig) error {
	var operators []cluster.Operator
	for _, opENR := range conf.OperatorENRs {
		operators = append(operators, cluster.Operator{
			ENR: opENR,
		})
	}

	if !validNetworks[conf.Network] {
		return errors.New("unsupported network", z.Str("network", conf.Network))
	}

	if err := validateWithdrawalAddr(conf.WithdrawalAddress, conf.Network); err != nil {
		return err
	}

	forkVersion := networkToForkVersion[conf.Network]

	def := cluster.NewDefinition(conf.Name, conf.NumValidators, conf.Threshold, conf.FeeRecipient, conf.WithdrawalAddress,
		forkVersion, operators, crand.Reader)

	def.DKGAlgorithm = conf.DKGAlgo

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
		return errors.New("invalid address")
	}

	// We cannot allow a zero withdrawal address on mainnet or gnosis.
	if (network == "mainnet" || network == "gnosis") &&
		addr == defaultWithdrawalAddr {
		return errors.New("zero address forbidden on this network", z.Str("network", network))
	}

	return nil
}
