/*
Copyright © 2021 Oisín Kyne <oisin@obol.tech>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/obolnetwork/charon/services/controller"
	"github.com/obolnetwork/charon/utils"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var beaconNodes string
var peerNodes string
var quiet bool
var verbose bool
var logLevel string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "charon",
	Short: "Charon - The Ethereum SSV middleware client",
	Long:  `Charon client(s) enable the division of Ethereum validator operation across a group of trusted parties using threshold cryptography.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		log.Info().Msg("No command specified, starting Charon as an SSV client")
		log.Info().Msgf("Configured beacon chain URI: %s", viper.GetString("beacon-node"))
		log.Info().Msgf("Configured logging level: %s", viper.GetString("log-level"))
		StartCoreService()
	},
	PersistentPreRunE: persistentPreRunE,
}

// Pre-run hook executed by all commands and subcommands unless they declare their own
// Used to parse and validate global config typically (for now it sets log level)
func persistentPreRunE(cmd *cobra.Command, args []string) error {
	if cmd.Name() == "help" {
		// User just wants help
		return nil
	}

	if cmd.Name() == "version" {
		// User just wants the version
		return nil
	}

	// We bind viper here so that we bind to the correct command.
	quiet = viper.GetBool("quiet")
	verbose = viper.GetBool("verbose")
	logLevel = viper.GetString("log-level")
	zerolog.SetGlobalLevel(utils.StringToLevel(logLevel))

	if quiet && verbose {
		fmt.Println("Cannot supply both quiet and verbose flags")
	}

	return nil
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

// Instantiates the Core Controller Service
func StartCoreService() error {
	ctx := context.Background()

	ctrl, err := controller.New(ctx)
	if err != nil {
		return err
	}
	ctrl.Start()
	return nil
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.charon.yaml)")
	rootCmd.PersistentFlags().StringVar(&beaconNodes, "beacon-node", "http://localhost:5051", "URI for beacon node API")
	if err := viper.BindPFlag("beacon-node", rootCmd.PersistentFlags().Lookup("beacon-node")); err != nil {
		panic(err)
	}
	rootCmd.PersistentFlags().StringVar(&peerNodes, "peers", "http://localhost:9001,http://localhost:9002,http://localhost:9003", "URIs of peer charon clients")
	if err := viper.BindPFlag("peers", rootCmd.PersistentFlags().Lookup("peers")); err != nil {
		panic(err)
	}
	rootCmd.PersistentFlags().Bool("quiet", false, "do not generate any output")
	if err := viper.BindPFlag("quiet", rootCmd.PersistentFlags().Lookup("quiet")); err != nil {
		panic(err)
	}
	rootCmd.PersistentFlags().Bool("verbose", false, "generate additional output where appropriate")
	if err := viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose")); err != nil {
		panic(err)
	}
	rootCmd.PersistentFlags().String("log-level", "info", "Logging Level (none, trace, debug, warn, info, err, fatal)")
	if err := viper.BindPFlag("log-level", rootCmd.PersistentFlags().Lookup("log-level")); err != nil {
		panic(err)
	}
}

// initConfig reads in config file and ENV variables if set and stores them in Viper
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".charon" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".charon")
	}

	viper.SetEnvPrefix("CHARON")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv() // read in environment variables that match

	if err := viper.ReadInConfig(); err != nil {
		// Don't report lack of config file...
		assert(strings.Contains(err.Error(), "Not Found"), "failed to read configuration")
	}
}
