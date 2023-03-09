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

	libp2plog "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/dkg"
)

func newDKGCmd(runFunc func(context.Context, dkg.Config) error) *cobra.Command {
	var config dkg.Config

	cmd := &cobra.Command{
		Use:   "dkg",
		Short: "Participate in a Distributed Key Generation ceremony",
		Long: `Participate in a distributed key generation ceremony for a specific cluster definition that creates
distributed validator key shares and a final cluster lock configuration. Note that all other cluster operators should run
this command at the same time.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := log.InitLogger(config.Log); err != nil {
				return err
			}
			libp2plog.SetPrimaryCore(log.LoggerCore()) // Set libp2p logger to use charon logger

			printFlags(cmd.Context(), cmd.Flags())

			return runFunc(cmd.Context(), config)
		},
	}

	bindDataDirFlag(cmd.Flags(), &config.DataDir)
	bindDefDirFlag(cmd.Flags(), &config.DefFile)
	bindNoVerifyFlag(cmd.Flags(), &config.NoVerify)
	bindP2PFlags(cmd, &config.P2P)
	bindLogFlags(cmd.Flags(), &config.Log)

	return cmd
}

func bindDefDirFlag(flags *pflag.FlagSet, dataDir *string) {
	flags.StringVar(dataDir, "definition-file", ".charon/cluster-definition.json", "The path to the cluster definition file or an HTTP URL.")
}

func bindDataDirFlag(flags *pflag.FlagSet, dataDir *string) {
	flags.StringVar(dataDir, "data-dir", ".charon", "The directory where charon will store all its internal data")
}
