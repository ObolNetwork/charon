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
//	It consists of multiple steps:
//	 - compose new: Creates a new config.json that defines what will be composed.
//	 - compose define: Creates a docker-compose.yml that executes `charon create dkg` if keygen==dkg.
//	 - compose lock: Creates a docker-compose.yml that executes `charon create cluster` or `charon dkg`.
//	 - compose run: Creates a docker-compose.yml that executes `charon run`.
package main

import (
	"context"
	"io/fs"
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
	root.AddCommand(newAutoCmd(nil))
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

// runFunc defines a function that generates docker-compose.yml from config and returns the template data.
type runFunc func(context.Context, string, compose.Config) (compose.TmplData, error)

// newRunnerFunc returns a function that wraps and runs a run function.
func newRunnerFunc(topic string, dir string, up bool, runFunc runFunc,
) func(ctx context.Context) (data compose.TmplData, err error) {
	return func(ctx context.Context) (data compose.TmplData, err error) {
		ctx = log.WithTopic(ctx, topic)
		defer func() {
			if err != nil {
				log.Error(ctx, "Fatal error", err)
			}
		}()

		conf, err := compose.LoadConfig(dir)
		if errors.Is(err, fs.ErrNotExist) {
			return compose.TmplData{}, errors.New("compose config.json not found; maybe try `compose new` first", z.Str("dir", dir))
		} else if err != nil {
			return compose.TmplData{}, err
		}

		log.Info(ctx, "Running compose command", z.Str("command", topic))

		data, err = runFunc(ctx, dir, conf)
		if err != nil {
			return compose.TmplData{}, err
		}

		if up {
			return data, execUp(ctx, dir)
		}

		return data, nil
	}
}

// newDockerCmd returns a cobra command that generates docker-compose.yml files and executes it.
func newDockerCmd(use string, short string, runFunc runFunc) *cobra.Command {
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
	}

	up := addUpFlag(cmd.Flags())
	dir := addDirFlag(cmd.Flags())
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		_, err := newRunnerFunc(use, *dir, *up, runFunc)(cmd.Context())
		if err != nil {
			log.Error(cmd.Context(), "Fatal error", err)
		}

		return err
	}

	return cmd
}

//nolint:gocognit // TODO(corver): Move this to compose package and improve API.
func newAutoCmd(tmplCallbacks map[string]func(data *compose.TmplData)) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auto",
		Short: "Convenience function that runs `compose define && compose lock && compose run`",
		Args:  cobra.NoArgs,
	}

	dir := addDirFlag(cmd.Flags())
	alertTimeout := cmd.Flags().Duration("alert-timeout", 0, "Timeout to collect alerts before shutdown. Zero disables timeout.")
	sudoPerms := cmd.Flags().Bool("sudo-perms", false, "Enables changing all compose artefacts file permissions using sudo.")
	printYML := cmd.Flags().Bool("print-yml", false, "Print generated docker-compose.yml files.")

	cmd.RunE = func(cmd *cobra.Command, _ []string) (err error) {
		defer func() {
			if err != nil {
				log.Error(cmd.Context(), "Fatal error", err)
			}
		}()
		runFuncs := map[string]func(context.Context) (compose.TmplData, error){
			"define": newRunnerFunc("define", *dir, false, compose.Define),
			"lock":   newRunnerFunc("lock", *dir, false, compose.Lock),
			"run":    newRunnerFunc("run", *dir, false, compose.Run),
		}

		rootCtx := log.WithTopic(cmd.Context(), "auto")

		var lastTmpl compose.TmplData
		for i, step := range []string{"define", "lock", "run"} {
			lastTmpl, err = runFuncs[step](rootCtx)
			if err != nil {
				return err
			}

			if *sudoPerms {
				if err := fixPerms(rootCtx, *dir); err != nil {
					return err
				}
			}

			if tmplCallbacks[step] != nil {
				tmplCallbacks[step](&lastTmpl)
				err := compose.WriteDockerCompose(*dir, lastTmpl)
				if err != nil {
					return err
				}
			}

			if *printYML {
				if err := printDockerCompose(rootCtx, *dir); err != nil {
					return err
				}
			}

			if i < len(runFuncs)-1 {
				if err := execUp(rootCtx, *dir); err != nil {
					return err
				}
			}
		}

		ctx := rootCtx
		if *alertTimeout != 0 {
			// Ensure everything is clean before we start with alert test.
			_ = execDown(rootCtx, *dir)

			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(rootCtx, *alertTimeout)
			defer cancel()
		}

		alerts := startAlertCollector(ctx, *dir)

		defer func() {
			_ = execDown(rootCtx, *dir)
		}()

		if err := execUp(ctx, *dir); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			return err
		}

		var (
			alertMsgs    []string
			alertSuccess bool
		)
		for alert := range alerts {
			if alert == alertsPolled {
				alertSuccess = true
			} else {
				alertMsgs = append(alertMsgs, alert)
			}
		}
		if !alertSuccess {
			log.Error(ctx, "Alerts couldn't be polled", nil)
			return nil // TODO(corver): Fix this and error
		} else if len(alertMsgs) > 0 {
			return errors.New("alerts detected", z.Any("alerts", alertMsgs))
		}

		log.Info(ctx, "No alerts detected")

		return nil
	}

	return cmd
}

// printDockerCompose prints the docker-compose.yml file to stdout.
func printDockerCompose(ctx context.Context, dir string) error {
	log.Info(ctx, "Printing docker-compose.yml")
	cmd := exec.CommandContext(ctx, "cat", "docker-compose.yml")
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		return errors.Wrap(err, "exec cat docker-compose.yml")
	}

	return nil
}

// fixPerms fixes file permissions as a workaround for linux docker by removing
// all restrictions using sudo chmod.
func fixPerms(ctx context.Context, dir string) error {
	cmd := exec.CommandContext(ctx, "sudo", "chmod", "-R", "a+wrX", ".")
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		return errors.Wrap(err, "exec sudo chmod")
	}

	return nil
}

func newNewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "new",
		Short: "Creates a new config.json that defines what will be composed",
	}

	conf := compose.NewDefaultConfig()

	dir := addDirFlag(cmd.Flags())
	keygen := cmd.Flags().String("keygen", string(conf.KeyGen), "Key generation process: create, split, dkg")
	buildLocal := cmd.Flags().Bool("build-local", conf.BuildBinary, "Enables building a local charon binary from source. Note this requires the CHARON_REPO env var.")
	beaconNode := cmd.Flags().String("beacon-node", conf.BeaconNode, "Beacon node URL endpoint or 'mock' for simnet.")
	extBootnode := cmd.Flags().String("external-bootnode", "", "Optional external bootnode HTTP url.")
	splitKeys := cmd.Flags().String("split-keys-dir", conf.SplitKeysDir, "Directory containing keys to split for keygen==create, or empty not to split.")
	featureSet := cmd.Flags().String("feature-set", conf.FeatureSet, "Minimum feature set to enable: alpha, beta, stable")
	numVals := cmd.Flags().Int("num-validators", conf.NumValidators, "Number of distributed validators.")
	vcTypes := cmd.Flags().StringSlice("validator-types", conf.VCStrings(), "Validator types to include.")

	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		conf.KeyGen = compose.KeyGen(*keygen)
		conf.BuildBinary = *buildLocal
		conf.BeaconNode = *beaconNode
		conf.SplitKeysDir = *splitKeys
		conf.FeatureSet = *featureSet
		conf.ExternalBootnode = *extBootnode
		conf.NumValidators = *numVals

		var vcs []compose.VCType
		for _, vc := range *vcTypes {
			vcs = append(vcs, compose.VCType(vc))
		}
		conf.VCs = vcs

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
	// Build first so containers start at the same time below.
	log.Info(ctx, "Executing docker-compose build")
	cmd := exec.CommandContext(ctx, "docker-compose", "build", "--parallel")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		return errors.Wrap(err, "exec docker-compose build", z.Str("output", string(out)))
	}

	log.Info(ctx, "Executing docker-compose up")
	cmd = exec.CommandContext(ctx, "docker-compose", "up",
		"--remove-orphans",
		"--abort-on-container-exit",
		"--quiet-pull",
	)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}

		return errors.Wrap(err, "exec docker-compose up")
	}

	return nil
}

// execDown executes `docker-compose down`.
func execDown(ctx context.Context, dir string) error {
	log.Info(ctx, "Executing docker-compose down")

	cmd := exec.CommandContext(ctx, "docker-compose", "down",
		"--remove-orphans",
		"--timeout=2",
	)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return errors.Wrap(err, "run down")
	}

	return nil
}
