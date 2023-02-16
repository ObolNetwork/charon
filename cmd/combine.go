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

func newCombineCmd(runFunc func(ctx context.Context, inputDir string, force bool) error) *cobra.Command {
	var (
		inputDir string
		force    bool
	)

	cmd := &cobra.Command{
		Use:   "combine",
		Short: "Combines private key shares into a single private key for a distributed validator.",
		Long:  "Combines private key shares into a single private key for a distributed validator.\nWarning: running the resulting private key in a validator alongside the original distributed validator will result in slashing.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFunc(cmd.Context(), inputDir, force)
		},
	}

	bindCombineFlags(
		cmd.Flags(),
		&inputDir,
		&force,
	)

	return cmd
}

func newCombineFunc(ctx context.Context, inputDir string, force bool) error {
	return combine.Combine2(ctx, inputDir, force)
}

func bindCombineFlags(flags *pflag.FlagSet, inputDir *string, force *bool) {
	flags.StringVar(inputDir, "keystore-dir", "./", `Directory containing all the keystore files organized by ENR, and the lock file.`)
	flags.BoolVar(force, "force", false, "Overwrites private keys with the same name if present.")
}
