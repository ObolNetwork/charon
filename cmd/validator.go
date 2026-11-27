// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util/vcfiles"
)

const (
	validatorClients = "<teku|prysm|lodestar|nimbus|lighthouse>"

	defaultValidatorConfigDir = ".charon/validator-config"
	defaultValidatorKeysDir   = ".charon/validator_keys"
)

func newValidatorCmd(cmds ...*cobra.Command) *cobra.Command {
	root := &cobra.Command{
		Use:   "validator",
		Short: "Write the files a validator client needs from this node's cluster artifacts",
		Long:  "Writes the files a validator client needs from this node's cluster artifacts: its proposer settings and flags with config, the key shares in its layout with keys.",
	}

	root.AddCommand(cmds...)

	return root
}

func newValidatorConfigCmd(runFunc func(context.Context, io.Writer, vcfiles.Config) error) *cobra.Command {
	var conf vcfiles.Config

	cmd := &cobra.Command{
		Use:   "config " + validatorClients,
		Short: "Write a validator client's proposer settings and flags from the proposer config",
		Long: "Writes a validator client's proposer settings in its own format and the flags a distributed validator needs, from the cluster's proposer config file. " +
			"It holds no keys. Run it again after the proposer config changes, then restart the validator client.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := setValidatorClient(&conf, args[0], defaultValidatorConfigDir)
			if err != nil {
				return err
			}

			return runFunc(cmd.Context(), cmd.OutOrStdout(), conf)
		},
	}

	f := cmd.Flags()
	f.StringVar(&conf.OutputDir, "output-dir", "", "The directory to write the settings and flags to. (default \""+defaultValidatorConfigDir+"/<client>\")")
	f.StringVar(&conf.ProposerConfigFile, "proposer-config-file", ".charon/vc-config/proposer-config.json", "The path to the proposer config file.")
	f.StringVar(&conf.ValidatorKeysDir, "validator-keys-dir", defaultValidatorKeysDir, "The path to the directory holding the validator key shares, whose public keys name the validators in prysm's, nimbus's and lighthouse's settings.")
	f.StringVar(&conf.LighthouseDir, "lighthouse-dir", "", "Lighthouse's data directory as Lighthouse sees it, e.g. /root/.lighthouse/hoodi. Its validator definitions name the keystores under it. Required for lighthouse.")
	f.BoolVar(&conf.BuilderAPI, "builder-api", false, "Enables builder proposals on the validator client without builders in the proposer config. Set it as for charon run, whose builder API serves them before the gloas fork.")

	return cmd
}

func newValidatorKeysCmd(runFunc func(context.Context, io.Writer, vcfiles.Config) error) *cobra.Command {
	var (
		conf vcfiles.Config
		yes  bool
	)

	cmd := &cobra.Command{
		Use:   "keys " + validatorClients,
		Short: "Copy this node's validator key shares into a validator client's layout",
		Long: "Copies this node's validator key shares into the layout a validator client reads them in, in a directory of its own beside them. " +
			"The original key shares are left unchanged. A directory that is not empty is replaced after asking: key shares left in it from before would be loaded by the validator client too.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := setValidatorClient(&conf, args[0], conf.ValidatorKeysDir)
			if err != nil {
				return err
			}

			err = replaceKeysDir(cmd.InOrStdin(), cmd.OutOrStdout(), conf.OutputDir, conf.ValidatorKeysDir, yes, isInteractive())
			if err != nil {
				return err
			}

			return runFunc(cmd.Context(), cmd.OutOrStdout(), conf)
		},
	}

	f := cmd.Flags()
	f.StringVar(&conf.OutputDir, "output-dir", "", "The directory to write the key shares to. (default \"<validator-keys-dir>/<client>\")")
	f.StringVar(&conf.ValidatorKeysDir, "validator-keys-dir", defaultValidatorKeysDir, "The path to the directory holding the validator key shares.")
	f.BoolVar(&yes, "yes", false, "Replace an output directory that is not empty without asking, for scripts.")

	return cmd
}

// replaceKeysDir deletes the output directory dir if it is not empty, after asking on in unless yes is set: key
// shares left in it from before would be loaded by the validator client beside the new ones.
func replaceKeysDir(in io.Reader, w io.Writer, dir, keysDir string, yes, interactive bool) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) || (err == nil && len(entries) == 0) {
		return nil
	} else if err != nil {
		return errors.Wrap(err, "read output directory", z.Str("path", dir))
	}

	inside, err := isInside(dir, keysDir)
	if err != nil {
		return err
	}

	if inside {
		return errors.New("output directory holds the validator key shares, it cannot be replaced", z.Str("path", dir))
	}

	if !yes {
		if !interactive {
			return errors.New("output directory is not empty, add --yes to replace it without asking", z.Str("path", dir))
		}

		_, _ = fmt.Fprintf(w, "Directory %s is not empty. Delete everything in it and write the key shares anew? [y/N] ", dir)

		line, err := bufio.NewReader(in).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return errors.Wrap(err, "read confirmation")
		}

		answer := strings.ToLower(strings.TrimSpace(line))
		if answer != "y" && answer != "yes" {
			return errors.New("replacing the output directory not confirmed, nothing was written", z.Str("path", dir))
		}
	}

	err = os.RemoveAll(dir)
	if err != nil {
		return errors.Wrap(err, "delete output directory", z.Str("path", dir))
	}

	return nil
}

// isInside returns true if path is dir or lies inside it.
func isInside(dir, path string) (bool, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return false, errors.Wrap(err, "absolute path", z.Str("path", dir))
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return false, errors.Wrap(err, "absolute path", z.Str("path", path))
	}

	rel, err := filepath.Rel(absDir, absPath)
	if err != nil {
		return false, errors.Wrap(err, "relative path", z.Str("path", path))
	}

	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))), nil
}

// setValidatorClient sets the config's client, and its output directory to the client's in defaultDir if unset.
func setValidatorClient(conf *vcfiles.Config, name, defaultDir string) error {
	client, err := vcfiles.ParseClient(name)
	if err != nil {
		return err
	}

	conf.Client = client
	if conf.OutputDir == "" {
		conf.OutputDir = filepath.Join(defaultDir, name)
	}

	return nil
}

func runValidatorConfig(ctx context.Context, w io.Writer, conf vcfiles.Config) error {
	files, err := vcfiles.WriteConfig(ctx, conf)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(w, "Proposer settings and flags for %s written to %s:\n", conf.Client, conf.OutputDir)
	for _, file := range files {
		_, _ = fmt.Fprintf(w, "  %s\n", file)
	}

	if conf.Client == vcfiles.Lighthouse {
		_, _ = fmt.Fprintf(w, "The definitions name the keystores under %s, move the validators and secrets directories there.\n", conf.LighthouseDir)
	}

	if conf.Client == vcfiles.Nimbus {
		_, _ = fmt.Fprintln(w, "Nimbus reads each validator's settings beside its keystore, merge the validators directory into the one charon alpha validator keys wrote.")
	}

	_, _ = fmt.Fprintf(w, "Append the lines of %s to the validator client's command.\n", vcfiles.FlagsFile)

	return nil
}

func runValidatorKeys(ctx context.Context, w io.Writer, conf vcfiles.Config) error {
	files, err := vcfiles.WriteKeys(ctx, conf)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(w, "Key shares for %s written to %s, the originals are unchanged:\n", conf.Client, conf.OutputDir)
	for _, file := range files {
		_, _ = fmt.Fprintf(w, "  %s\n", file)
	}

	if conf.Client == vcfiles.Prysm {
		_, _ = fmt.Fprintf(w, "Point prysm's --wallet-dir at the %s directory, no import needed.\n", vcfiles.PrysmWalletDir)
	}

	return nil
}
