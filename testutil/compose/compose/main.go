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
//  It consists of multiple steps:
//   - compose new: Creates a new config.json that defines what will be composed.
//   - compose define: Creates a docker-compose.yml that executes `charon create dkg` if keygen==dkg.
//   - compose lock: Creates a docker-compose.yml that executes `charon create cluster` or `charon dkg`.
//   - compose run: Creates a docker-compose.yml that executes `charon run`.
package main

import (
	"context"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
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

	root.AddCommand(newNewCmd())
	root.AddCommand(newCleanCmd())
	root.AddCommand(newAutoCmd())
	root.AddCommand(newDockerCmd(
		"define",
		"Creates a docker-compose.yml that executes `charon create dkg` if keygen==dkg",
		compose.Define,
	))
	root.AddCommand(newDockerCmd(
		"lock",
		"Creates a docker-compose.yml that executes `charon create cluster` or `charon dkg`",
		compose.Lock,
	))
	root.AddCommand(newDockerCmd(
		"run",
		"Creates a docker-compose.yml that executes `charon run`",
		compose.Run,
	))

	return root
}

// newDockerRunFunc returns a cobra run function that generates docker-compose.yml files and executes it.
func newDockerRunFunc(topic string, dir *string, up *bool, runFunc func(context.Context, string) error) func(cmd *cobra.Command, _ []string) error {
	return func(cmd *cobra.Command, _ []string) (err error) {
		ctx := log.WithTopic(cmd.Context(), topic)
		defer func() {
			if err != nil {
				log.Error(ctx, "Fatal error", err)
			}
		}()

		log.Info(ctx, "Running compose command", z.Str("command", topic))

		if err := runFunc(ctx, *dir); err != nil {
			return err
		}

		if *up {
			return execUp(ctx, *dir)
		}

		return nil
	}
}

// newDockerCmd returns a cobra command that generates docker-compose.yml files and executes it.
func newDockerCmd(use string, short string, run func(context.Context, string) error) *cobra.Command {
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
	}

	up := addUpFlag(cmd.Flags())
	dir := addDirFlag(cmd.Flags())
	cmd.RunE = newDockerRunFunc(use, dir, up, run)

	return cmd
}

func newAutoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auto",
		Short: "Convenience function that runs `compose define && compose lock && compose run`",
	}

	dir := addDirFlag(cmd.Flags())
	up := true

	runFuncs := []func(cmd *cobra.Command, _ []string) (err error){
		newDockerRunFunc("define", dir, &up, compose.Define),
		newDockerRunFunc("lock", dir, &up, compose.Lock),
		newDockerRunFunc("run", dir, &up, compose.Run),
	}

	cmd.RunE = func(cmd *cobra.Command, _ []string) (err error) {
		for _, runFunc := range runFuncs {
			err := runFunc(cmd, nil)
			if err != nil {
				return err
			}
		}

		return nil
	}

	return cmd
}

func newNewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "new",
		Short: "Creates a new config.json that defines what will be composed",
	}

	conf := compose.NewDefaultConfig()

	dir := addDirFlag(cmd.Flags())
	keygen := cmd.Flags().String("keygen", string(conf.KeyGen), "Key generation process: create, split, dkg")
	buildLocal := cmd.Flags().Bool("build-local", conf.BuildLocal, "Enables building a local charon binary from source. Note this requires the CHARON_REPO env var.")

	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		conf.KeyGen = compose.KeyGen(*keygen)
		conf.BuildLocal = *buildLocal

		ctx := log.WithTopic(cmd.Context(), "new")
		if err := compose.New(ctx, *dir, conf); err != nil {
			log.Error(ctx, "Fatal error", err)
			return err
		}

		return nil
	}

	return cmd
}

func newCleanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "clean",
		Short: "Convenience function that cleans the compose directory",
	}

	dir := addDirFlag(cmd.Flags())

	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		return compose.Clean(cmd.Context(), *dir)
	}

	return cmd
}

func addDirFlag(flags *pflag.FlagSet) *string {
	return flags.String("compose-dir", ".", "Directory to use for compose artifacts")
}

func addUpFlag(flags *pflag.FlagSet) *bool {
	return flags.Bool("up", true, "Execute `docker-compose up` when compose command completes")
}

// execUp executes `docker-compose up`.
func execUp(ctx context.Context, dir string) error {
	log.Info(ctx, "Executing docker-compose up")

	cmd := exec.CommandContext(ctx, "docker-compose", "up", "--remove-orphans", "--build")
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return errors.Wrap(err, "run up")
	}

	return nil
}
