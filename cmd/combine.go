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

	"github.com/obolnetwork/charon/combine"
)

func newCombineCmd(runFunc func(ctx context.Context, keystoresDir string, force bool) error) *cobra.Command {
	var (
		keystoresDir string
		force        bool
	)

	cmd := &cobra.Command{
		Use:   "combine",
		Short: "Combines the private key shares of a distributed validator cluster into a set of standard validator private keys.",
		Long:  "Combines the private key shares from a threshold of operators in a distributed validator cluster into a set of validator private keys that can be imported into a standard Ethereum validator client.\n\nWarning: running the resulting private keys in a validator alongside the original distributed validator cluster *will* result in slashing.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFunc(cmd.Context(), keystoresDir, force)
		},
	}

	bindCombineFlags(
		cmd.Flags(),
		&keystoresDir,
		&force,
	)

	return cmd
}

func newCombineFunc(ctx context.Context, keystoresDir string, force bool) error {
	return combine.Combine(ctx, keystoresDir, force)
}

func bindCombineFlags(flags *pflag.FlagSet, keystoresDir *string, force *bool) {
	flags.StringVar(keystoresDir, "keystores-dir", "./", `Directory containing all the keystore files organized by ENR, and the lock file.`)
	flags.BoolVar(force, "force", false, "Overwrites private keys with the same name if present.")
}
