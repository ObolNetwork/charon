// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"io"
	dbg "runtime/debug"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/obolnetwork/charon/internal"
)

type versionConfig struct {
	Verbose bool
}

// newVersionCmd returns the version command
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
	fmt.Fprintln(out, internal.ReleaseVersion)

	if !config.Verbose {
		return
	}

	buildInfo, ok := dbg.ReadBuildInfo()

	if !ok {
		fmt.Fprintf(out, "\nFailed to gather build info")
		return
	}

	fmt.Fprintf(out, "Package: %s\n", buildInfo.Path)
	fmt.Fprintf(out, "Dependencies:")

	for _, dep := range buildInfo.Deps {
		for dep.Replace != nil {
			dep = dep.Replace
		}
		fmt.Fprintf(out, "\t%v %v\n", dep.Path, dep.Version)
	}
}
