// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package cmd implements Charon's command-line interface.
package cmd

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cmd/relay"
	"github.com/obolnetwork/charon/dkg"
)

const (
	// The name of our config file, without the file extension because
	// viper supports many different config file languages.
	defaultConfigFilename = "charon"

	// The environment variable prefix of all environment variables bound to our command line flags.
	envPrefix   = "charon"
	httpScheme  = "http"
	httpsScheme = "https"
)

// New returns a new root cobra command that handles our command line tool.
func New() *cobra.Command {
	return newRootCmd(
		newVersionCmd(runVersionCmd),
		newEnrCmd(runNewENR),
		newRunCmd(app.Run, false),
		newRelayCmd(relay.Run),
		newDKGCmd(dkg.Run),
		newCreateCmd(
			newCreateDKGCmd(runCreateDKG),
			newCreateEnrCmd(runCreateEnrCmd),
			newCreateClusterCmd(runCreateCluster),
		),
		newCombineCmd(newCombineFunc),
		newAlphaCmd(
			newTestCmd(
				newTestAllCmd(runTestAll),
				newTestPeersCmd(runTestPeers),
				newTestBeaconCmd(runTestBeacon),
				newTestValidatorCmd(runTestValidator),
				newTestMEVCmd(runTestMEV),
				newTestInfraCmd(runTestInfra),
			),
			newAddValidatorsCmd(runAddValidatorsSolo),
			newViewClusterManifestCmd(runViewClusterManifest),
		),
		newExitCmd(
			newListActiveValidatorsCmd(runListActiveValidatorsCmd),
			newSignPartialExitCmd(runSignPartialExit),
			newBcastFullExitCmd(runBcastFullExit),
			newFetchExitCmd(runFetchExit),
		),
		newUnsafeCmd(newRunCmd(app.Run, true)),
	)
}

func newRootCmd(cmds ...*cobra.Command) *cobra.Command {
	root := &cobra.Command{
		Use:   "charon",
		Short: "Charon - Proof of Stake Ethereum Distributed Validator Client",
		Long:  `Charon enables the operation of Ethereum validators in a fault tolerant manner by splitting the validating keys across a group of trusted parties using threshold cryptography.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error { //nolint:revive // keep args variable name for clarity
			return initializeConfig(cmd)
		},
	}

	root.AddCommand(cmds...)
	root.SilenceErrors = true // Disable default error printing.

	titledHelp(root)
	silenceUsage(root)

	return root
}

// silenceUsage silences the usage printing when commands error during "running",
// so only show usage if error occurs before that, e.g., when parsing flags.
func silenceUsage(cmd *cobra.Command) {
	if runFunc := cmd.RunE; runFunc != nil {
		cmd.RunE = func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return runFunc(cmd, args)
		}
	}

	for _, cmd := range cmd.Commands() {
		silenceUsage(cmd)
	}
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
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

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

// titledHelp updates the command (and child commands) help flag usage to title case.
func titledHelp(cmd *cobra.Command) {
	cmd.InitDefaultHelpFlag()
	f := cmd.Flags().Lookup("help")
	f.Usage = strings.ToUpper(f.Usage[:1]) + f.Usage[1:]

	for _, child := range cmd.Commands() {
		titledHelp(child)
	}
}

// printFlags INFO logs all the given flags in alphabetical order.
func printFlags(ctx context.Context, flags *pflag.FlagSet) {
	log.Info(ctx, "Parsed config", flagsToLogFields(flags)...)
}

// printLicense INFO logs the license notice.
func printLicense(ctx context.Context) {
	log.Info(ctx, "This software is licensed under the Maria DB Business Source License 1.1; "+
		"you may not use this software except in compliance with this license. "+
		"You may obtain a copy of this license at https://github.com/ObolNetwork/charon/blob/main/LICENSE")
}

// flagsToLogFields converts the given flags to log fields.
func flagsToLogFields(flags *pflag.FlagSet) []z.Field {
	var fields []z.Field
	flags.VisitAll(func(flag *pflag.Flag) {
		val := redact(flag.Name, flag.Value.String())

		if sliceVal, ok := flag.Value.(pflag.SliceValue); ok {
			var vals []string
			for _, s := range sliceVal.GetSlice() {
				vals = append(vals, redact(flag.Name, s))
			}
			val = "[" + strings.Join(vals, ",") + "]"
		}

		fields = append(fields, z.Str(flag.Name, val))
	})

	return fields
}

// redact returns a redacted version of the given flag value. It currently supports redacting
// passwords in valid URLs provided in ".*address.*" flags and redacting auth tokens.
func redact(flag, val string) string {
	if strings.Contains(flag, "auth-token") {
		return "xxxxx"
	}

	if !strings.Contains(flag, "address") {
		return val
	}

	u, err := url.ParseRequestURI(val)
	if err != nil {
		return val
	}

	return u.Redacted()
}
