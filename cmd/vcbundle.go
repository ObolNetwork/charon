// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"slices"

	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/eth2util/vcbundle"
)

func newVCBundleCmd(runFunc func(context.Context, io.Writer, vcbundle.Config) error) *cobra.Command {
	var (
		conf    vcbundle.Config
		include []string
	)

	cmd := &cobra.Command{
		Use:   "vc-bundle <teku|prysm|lodestar|nimbus|lighthouse>",
		Short: "Write the files a validator client needs from this node's cluster artifacts",
		Long: "Writes the files a validator client needs from this node's cluster artifacts: the validator keystores in its layout, " +
			"its proposer settings and the flags a distributed validator needs, to move into the validator client's directory.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := vcbundle.ParseClient(args[0])
			if err != nil {
				return err
			}

			parts, err := vcbundle.ParseParts(include)
			if err != nil {
				return err
			}

			conf.Client, conf.Parts = client, parts

			return runFunc(cmd.Context(), cmd.OutOrStdout(), conf)
		},
	}

	var defaultParts []string
	for _, p := range vcbundle.AllParts() {
		defaultParts = append(defaultParts, string(p))
	}

	f := cmd.Flags()
	f.StringSliceVar(&include, "include", defaultParts, "Comma-separated parts of the bundle to write: keystores, proposer-settings, vc-flags.")
	f.StringVar(&conf.OutputDir, "output-dir", ".charon/vc-bundle", "The directory to write the bundle to.")
	f.StringVar(&conf.ProposerConfigFile, "proposer-config-file", ".charon/vc-config/proposer-config.json", "The path to the proposer config file.")
	f.StringVar(&conf.ValidatorKeysDir, "validator-keys-dir", ".charon/validator_keys", "The path to the directory holding the validator key shares. Lighthouse reads them there, at their absolute path.")

	return cmd
}

func runVCBundle(ctx context.Context, w io.Writer, conf vcbundle.Config) error {
	files, err := vcbundle.Write(ctx, conf)
	if err != nil {
		return err
	}

	if len(files) == 0 {
		_, _ = fmt.Fprintln(w, "Nothing to write: Lighthouse reads the keystores in place.")
		return nil
	}

	_, _ = fmt.Fprintf(w, "Validator client bundle for %s written to %s:\n", conf.Client, conf.OutputDir)
	for _, file := range files {
		_, _ = fmt.Fprintf(w, "  %s\n", file)
	}

	_, _ = fmt.Fprintln(w, "Move these files into the validator client's directory.")

	if conf.Client == vcbundle.Lighthouse && slices.Contains(conf.Parts, vcbundle.PartProposerSettings) {
		keysDir, err := filepath.Abs(conf.ValidatorKeysDir)
		if err != nil {
			return errors.Wrap(err, "absolute validator keys path")
		}

		_, _ = fmt.Fprintf(w, "The definitions point at the keystores in %s, Lighthouse must see them at that path.\n", keysDir)
	}

	if slices.Contains(files, vcbundle.FlagsFile) {
		_, _ = fmt.Fprintf(w, "Append the lines of %s to the validator client's command.\n", vcbundle.FlagsFile)
	}

	return nil
}
