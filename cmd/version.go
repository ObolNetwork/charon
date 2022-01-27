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
	dbg "runtime/debug"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/obolnetwork/charon/internal"
	"github.com/obolnetwork/charon/internal/config"
)

// versionCmd represents the version command.
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version and exit",
	Long:  "Output version info. Use --verbose for detailed module version info.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(internal.ReleaseVersion)
		if viper.GetBool(config.KeyVerbose) {
			printBuildInfo()
		}
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

func printBuildInfo() {
	buildInfo, ok := dbg.ReadBuildInfo()
	if !ok {
		fmt.Println("Failed to gather build info")
		return
	}
	fmt.Printf("Package: %s\n", buildInfo.Path)
	fmt.Println("Dependencies:")
	for _, dep := range buildInfo.Deps {
		for dep.Replace != nil {
			dep = dep.Replace
		}
		fmt.Printf("\t%v %v\n", dep.Path, dep.Version)
	}
}
