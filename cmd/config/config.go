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

package config

import (
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func BindRunnerFlags(flags *pflag.FlagSet, config *RunnerConfig) {
	flags.String(KeyConfigFile, "", "Path to config file (default \"./charon.yml\")")

	config.ClusterFilepath = *flags.String(KeyClustersDir, "./clusters", "Path to clusters dir")

	config.DataDir = *flags.String(KeyDataDir, "./data", "Path to data dir")

	config.BeaconNodeUrl = *flags.String(KeyBeaconNode, "http://localhost:5051", "URL to Eth2 Beacon API")

	config.LogLevel = *flags.String(KeyLogLevel, "info", "Default log level")

	config.ControlPlaneApi.Address = *flags.String(KeyAPI, ":8088", "Control-plane API listen address")

	config.VerboseFlag = *flags.Bool(KeyVerbose, false, "Verbose output?")
}

func init() {
	viper.SetDefault(KeyValidators, []string(nil))
}

// StartTime is the time at which the application was started.
var StartTime = time.Now()

// LoadViper loads additional config keys from the config file and environment.
func LoadViper(configPath string) error {
	viper.SetEnvPrefix("charon")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	viper.AutomaticEnv() // read in environment variables that match
	if configPath != "" {
		viper.SetConfigFile(configPath)
		return viper.ReadInConfig()
	}
	return nil
}
