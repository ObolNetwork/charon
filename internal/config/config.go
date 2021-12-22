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

// Common config keys.
const (
	KeyDataDir     = "data-dir"
	KeyClustersDir = "clusters-dir"
	KeyConfigFile  = "config-file"
	KeyBeaconNode  = "beacon-node"
	KeyLogLevel    = "log-level"
	KeyListen      = "listen"
	KeyListenAPI   = "listen-api"
	KeyVerbose     = "verbose"
	KeyValidators  = "validators"
)

func init() {
	viper.SetDefault(KeyValidators, []string(nil))
}

// StartTime is the time at which the application was started.
var StartTime = time.Now()

// CommonFlags sets up Charon's common flags.
//
// Must only be called once in the program's lifetime.
func CommonFlags(flags *pflag.FlagSet) {
	flags.String(KeyConfigFile, "", "Path to config file (default \"./charon.yml\")")

	flags.String(KeyClustersDir, "./clusters", "Path to clusters dir")
	MustBindPFlag(KeyClustersDir, flags)

	flags.String(KeyDataDir, "./data", "Path to data dir")
	MustBindPFlag(KeyDataDir, flags)

	flags.String(KeyBeaconNode, "http://localhost:5051", "URL to Eth2 Beacon API")
	MustBindPFlag(KeyBeaconNode, flags)

	flags.String(KeyLogLevel, "info", "Default log level")
	MustBindPFlag(KeyLogLevel, flags)

	flags.String(KeyListen, ":8087", "Beacon validator API listen address")
	MustBindPFlag(KeyListen, flags)

	flags.String(KeyListenAPI, ":8088", "Control-plane API listen address")
	MustBindPFlag(KeyListenAPI, flags)

	flags.Bool(KeyVerbose, false, "Verbose output?")
	MustBindPFlag(KeyVerbose, flags)

	P2PFlags(flags)
}

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

// MustBindPFlag binds the flag in the given flag set to the viper key of the same name.
//
// Panics if binding fails.
func MustBindPFlag(key string, flags *pflag.FlagSet) {
	flag := flags.Lookup(key)
	if flag == nil {
		panic("unknown flag: " + key)
	}
	err := viper.BindPFlag(key, flag)
	if err != nil {
		panic(err.Error())
	}
}
