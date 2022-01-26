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
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	_ "go.uber.org/automaxprocs" // Automatically sets GOMAXPROCS to match Linux container CPU quota.

	"github.com/obolnetwork/charon/internal/config"
)

// rootCmd is the root of the command tree.
var rootCmd = &cobra.Command{
	Use:   "charon",
	Short: "Charon - The Ethereum DVT middleware client",
	Long:  `Charon enables the operation of Ethereum validators in a fault tolerant manner by splitting the validating keys across a group of trusted parties using threshold cryptography.`,

	PersistentPreRunE: preRunRoot,
}

func init() {
	config.CommonFlags(rootCmd.PersistentFlags())
}

// Main executes the charon application.
func Main() {
	cobra.CheckErr(rootCmd.Execute())
}

// Pre-run hook executed by all commands and subcommands unless they declare their own
// Used to parse and validate global config typically (for now it sets log level)
func preRunRoot(c *cobra.Command, _ []string) error {
	// Set config file path from flag.
	configFileFlag, err := c.Flags().GetString(config.KeyConfigFile)
	if err != nil {
		return err
	}
	// Load config.
	if err := config.LoadViper(configFileFlag); err != nil {
		return err
	}
	// Set global log level.
	logLevel := viper.GetString(config.KeyLogLevel)
	lvl, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		return err
	}
	zerolog.SetGlobalLevel(lvl)

	return err
}

// log is a convenience handle to the global logger.
var log = zerologger.Logger
