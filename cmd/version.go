// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"fmt"
	"io"
	"runtime/debug"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/obolnetwork/charon/app/version"
)

type versionConfig struct {
	Verbose bool
}

// newVersionCmd returns the version command.
func newVersionCmd(runFunc func(io.Writer, versionConfig)) *cobra.Command {
	var conf versionConfig

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version and exit",
		Long:  "Output version info",
		Run: func(cmd *cobra.Command, args []string) {
			runFunc(cmd.OutOrStdout(), conf)
		},
	}

	bindVersionFlags(cmd.Flags(), &conf)

	return cmd
}

func bindVersionFlags(flags *pflag.FlagSet, config *versionConfig) {
	flags.BoolVar(&config.Verbose, "verbose", false, "Includes detailed module version info")
}

func runVersionCmd(out io.Writer, config versionConfig) {
	hash, timestamp := version.GitCommit()
	_, _ = fmt.Fprintf(out, "%v [git_commit_hash=%s,git_commit_time=%s]\n", version.Version, hash, timestamp)

	if !config.Verbose {
		return
	}

	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		_, _ = fmt.Fprintf(out, "\nFailed to gather build info")
		return
	}

	_, _ = fmt.Fprintf(out, "Package: %s\n", buildInfo.Path)
	_, _ = fmt.Fprint(out, "Dependencies:\n")

	for _, dep := range buildInfo.Deps {
		for dep.Replace != nil {
			dep = dep.Replace
		}
		_, _ = fmt.Fprintf(out, "\t%v %v\n", dep.Path, dep.Version)
	}
}
