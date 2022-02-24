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

// Package cmd implements Charon's command-line interface.
package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/errors"
)

const (
	// The name of our config file, without the file extension because
	// viper supports many different config file languages.
	defaultConfigFilename = "charon"

	// The environment variable prefix of all environment variables bound to our command line flags.
	envPrefix = "charon"
)

// New returns a new root cobra command that handles our command line tool.
func New() *cobra.Command {
	return newRootCmd(
		newVersionCmd(runVersionCmd),
		newEnrCmd(runNewENR),
		newRunCmd(app.Run),
		newGenSimnetCmd(runGenSimnet),
	)
}

func newRootCmd(cmds ...*cobra.Command) *cobra.Command {
	root := &cobra.Command{
		Use:   "charon",
		Short: "Charon - The Ethereum DVT middleware client",
		Long:  `Charon enables the operation of Ethereum validators in a fault tolerant manner by splitting the validating keys across a group of trusted parties using threshold cryptography.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return initializeConfig(cmd)
		},
	}

	root.AddCommand(cmds...)

	return root
}

// initializeConfig sets up the general viper config and binds the cobra flags to the viper flags.
func initializeConfig(cmd *cobra.Command) error {
	v := viper.New()

	v.SetConfigName(defaultConfigFilename)
	v.AddConfigPath(".")

	// Attempt to read the config file, gracefully ignoring errors
	// caused by a config file not being found. Return an error
	// if we cannot parse the config file.
	if err := v.ReadInConfig(); err != nil {
		// It's okay if there isn't a config file
		var cfgError viper.ConfigFileNotFoundError
		if ok := errors.As(err, &cfgError); !ok {
			return errors.Wrap(err, "read config")
		}
	}

	v.SetEnvPrefix(envPrefix)
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))

	// Bind the current command's flags to viper
	return bindFlags(cmd, v)
}

// bindFlags binds each cobra flag to its associated viper configuration (config file and environment variable).
func bindFlags(cmd *cobra.Command, v *viper.Viper) error {
	var lastErr error

	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		// Cobra provided flags take priority
		if f.Changed {
			return
		}

		// Define all the viper flag names to check
		viperNames := []string{
			f.Name,
			strings.ReplaceAll(f.Name, "_", "."), // TOML uses "." to indicate hierarchy, while we use "_" in this example.
		}

		for _, name := range viperNames {
			if !v.IsSet(name) {
				continue
			}

			val := v.Get(name)
			err := cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val))
			if err != nil {
				lastErr = err
			}

			break
		}
	})

	return lastErr
}
