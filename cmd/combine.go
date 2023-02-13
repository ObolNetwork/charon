package cmd

import (
	"context"
	"github.com/obolnetwork/charon/combine"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func newCombineCmd(runFunc func(lockfile, inputDir, outputDir string) error) *cobra.Command {
	var (
		inputDir  string
		outputDir string
		lockfile  string
	)

	cmd := &cobra.Command{
		Use:   "combine",
		Short: "Combines private key shares into a single private key for a distributed validator.",
		Long:  "Combines private key shares into a single private key for a distributed validator.\nWarning: running the resulting private key in a validator alongside the original distributed validator will result in slashing.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFunc(lockfile, inputDir, outputDir)
		},
	}

	bindVars(
		cmd.Flags(),
		&inputDir,
		&outputDir,
		&lockfile,
	)

	return cmd
}

func newCombineFunc(lockfile, inputDir, outputDir string) error {
	ctx := context.Background()
	return combine.Combine(ctx, lockfile, inputDir, outputDir)
}

func bindVars(flags *pflag.FlagSet, inputDir, outputDir, lockfile *string) {
	flags.StringVar(inputDir, "keyfile-dir", "./validator-keys", `Directory containing all the "keyfile-N.json" and "keyfile-N.txt" files`)
	flags.StringVar(outputDir, "out-dir", "./recombined-validator-key", "Directory where to save the resulting private key")
	flags.StringVar(lockfile, "lockfile-path", "./lock.json", "Charon lock.json file")
}
