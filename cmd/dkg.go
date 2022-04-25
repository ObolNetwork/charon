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

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/obolnetwork/charon/dkg"
)

func newDKGCmd(cmds ...*cobra.Command) *cobra.Command {
	dkg := &cobra.Command{
		Use:   "dkg",
		Short: "Lead or join a distributed key generation ceremony",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return initializeConfig(cmd)
		},
	}

	dkg.AddCommand(cmds...)

	titledHelp(dkg)

	return dkg
}

func newDKGJoinCommand(runFunc func(context.Context, dkg.JoinConfig) error) *cobra.Command {
	var conf dkg.JoinConfig

	cmd := &cobra.Command{
		Use:   "join",
		Short: "Join a dkg ceremony",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFunc(cmd.Context(), conf)
		},
	}

	bindDataDirFlag(cmd.Flags(), &conf.DataDir)
	bindP2PFlags(cmd.Flags(), &conf.P2PConfig)
	bindLogFlags(cmd.Flags(), &conf.LogConfig)
	bindDKGFlags(cmd.Flags(), &conf.ClusterConfig)

	return cmd
}

func newDKGLeadCommand(runFunc func(context.Context, dkg.LeadConfig) error) *cobra.Command {
	var conf dkg.LeadConfig

	cmd := &cobra.Command{
		Use:   "lead",
		Short: "Lead a dkg ceremony",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFunc(cmd.Context(), conf)
		},
	}

	bindDataDirFlag(cmd.Flags(), &conf.DataDir)
	bindP2PFlags(cmd.Flags(), &conf.P2PConfig)
	bindLogFlags(cmd.Flags(), &conf.LogConfig)
	bindDKGFlags(cmd.Flags(), &conf.ClusterConfig)

	return cmd
}

func bindDKGFlags(flags *pflag.FlagSet, config *dkg.ClusterConfig) {
	flags.IntVar(&config.Validators, "validators", 1, "The number of distributed validators (each requiring 32 ETH) to generate.")
	flags.IntVarP(&config.Threshold, "threshold", "t", 3, "The threshold required for signature reconstruction. Minimum is n-(ceil(n/3)-1).")
}
