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
	"fmt"
	"io"
	"runtime/debug"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/obolnetwork/charon/app"
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
	hash, timestamp := app.GitCommit()
	_, _ = fmt.Fprintf(out, "%s [git_commit_hash=%s,git_commit_time=%s]\n", version.Version, hash, timestamp)

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
