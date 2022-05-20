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

// Command compose provides a tool to run, test, debug local charon clusters
// using docker-compose.
//
//  It consists of three steps:
//   - compose define: Creates charon-compose.yml (and p2pkeys) that defines a desired cluster including keygen.
//   - compose lock: Creates docker-compose.yml to generates keys and cluster lock file.
//   - compose run: Creates docker-compose.yml that runs the cluster.
package main

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/testutil/compose"
)

func main() {
	cobra.CheckErr(newRootCmd().Execute())
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "compose",
		Short: "Charon Compose - Run, test, and debug a developer-focussed insecure local charon cluster using docker-compose",
	}

	root.AddCommand(newDefineCmd())
	root.AddCommand(newLockCmd())
	root.AddCommand(newRunCmd())

	return root
}

func newRunCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Create a docker-compose.yml from charon-compose.yml to run the cluster.",
	}

	dir := addDirFlag(cmd)

	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		return compose.Run(cmd.Context(), *dir)
	}

	return cmd
}

func newLockCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lock",
		Short: "Create a docker-compose.yml from charon-compose.yml for generating keys and a cluster lock file.",
	}

	dir := addDirFlag(cmd)

	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		return compose.Lock(cmd.Context(), *dir)
	}

	return cmd
}

func newDefineCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "define",
		Short: "Create a charon-compose.yml definition; including both keygen and running definitions",
	}

	dir := addDirFlag(cmd)
	clean := cmd.Flags().Bool("clean", true, "Clean compose dir before defining a new cluster")
	seed := cmd.Flags().Int("seed", int(time.Now().UnixNano()), "Randomness seed")

	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		return compose.Define(cmd.Context(), *dir, *clean, *seed)
	}

	return cmd
}

func addDirFlag(cmd *cobra.Command) *string {
	return cmd.Flags().String("compose-dir", ".", "Directory to use for compose artifacts")
}
