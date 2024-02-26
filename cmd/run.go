// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"net/url"
	"time"

	libp2plog "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/p2p"
)

func newRunCmd(runFunc func(context.Context, app.Config) error, unsafe bool) *cobra.Command {
	var conf app.Config

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the charon middleware client",
		Long:  "Starts the long-running Charon middleware process to perform distributed validator duties.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := log.InitLogger(conf.Log); err != nil {
				return err
			}
			libp2plog.SetPrimaryCore(log.LoggerCore()) // Set libp2p logger to use charon logger

			printFlags(cmd.Context(), cmd.Flags())

			return runFunc(cmd.Context(), conf)
		},
	}

	if unsafe {
		bindUnsafeRunFlags(cmd, &conf)
	}

	bindPrivKeyFlag(cmd, &conf.PrivKeyFile, &conf.PrivKeyLocking)
	bindRunFlags(cmd, &conf)
	bindDebugMonitoringFlags(cmd, &conf.MonitoringAddr, &conf.DebugAddr, "127.0.0.1:3620")
	bindNoVerifyFlag(cmd.Flags(), &conf.NoVerify)
	bindP2PFlags(cmd, &conf.P2P)
	bindLogFlags(cmd.Flags(), &conf.Log)
	bindLokiFlags(cmd.Flags(), &conf.Log)
	bindFeatureFlags(cmd.Flags(), &conf.Feature)

	return cmd
}

// bindLokiFlags binds the loki flags to the config.
// Note all commands that use this MUST also call log.SetLokiLabels
// or logs will not be sent to loki.
func bindLokiFlags(flags *pflag.FlagSet, config *log.Config) {
	flags.StringSliceVar(&config.LokiAddresses, "loki-addresses", nil, "Enables sending of logfmt structured logs to these Loki log aggregation server addresses. This is in addition to normal stderr logs.")
	flags.StringVar(&config.LokiService, "loki-service", "charon", "Service label sent with logs to Loki.")
}

func bindNoVerifyFlag(flags *pflag.FlagSet, config *bool) {
	flags.BoolVar(config, "no-verify", false, "Disables cluster definition and lock file verification.")
}

func bindRunFlags(cmd *cobra.Command, config *app.Config) {
	cmd.Flags().StringVar(&config.LockFile, "lock-file", ".charon/cluster-lock.json", "The path to the cluster lock file defining distributed validator cluster. If both cluster manifest and cluster lock files are provided, the cluster manifest file takes precedence.")
	cmd.Flags().StringVar(&config.ManifestFile, "manifest-file", ".charon/cluster-manifest.pb", "The path to the cluster manifest file. If both cluster manifest and cluster lock files are provided, the cluster manifest file takes precedence.")
	cmd.Flags().StringSliceVar(&config.BeaconNodeAddrs, "beacon-node-endpoints", nil, "Comma separated list of one or more beacon node endpoint URLs.")
	cmd.Flags().StringVar(&config.ValidatorAPIAddr, "validator-api-address", "127.0.0.1:3600", "Listening address (ip and port) for validator-facing traffic proxying the beacon-node API.")
	cmd.Flags().StringVar(&config.JaegerAddr, "jaeger-address", "", "Listening address for jaeger tracing.")
	cmd.Flags().StringVar(&config.JaegerService, "jaeger-service", "charon", "Service name used for jaeger tracing.")
	cmd.Flags().BoolVar(&config.SimnetBMock, "simnet-beacon-mock", false, "Enables an internal mock beacon node for running a simnet.")
	cmd.Flags().BoolVar(&config.SimnetVMock, "simnet-validator-mock", false, "Enables an internal mock validator client when running a simnet. Requires simnet-beacon-mock.")
	cmd.Flags().StringVar(&config.SimnetValidatorKeysDir, "simnet-validator-keys-dir", ".charon/validator_keys", "The directory containing the simnet validator key shares.")
	cmd.Flags().BoolVar(&config.BuilderAPI, "builder-api", false, "Enables the builder api. Will only produce builder blocks. Builder API must also be enabled on the validator client. Beacon node must be connected to a builder-relay to access the builder network.")
	cmd.Flags().BoolVar(&config.SyntheticBlockProposals, "synthetic-block-proposals", false, "Enables additional synthetic block proposal duties. Used for testing of rare duties.")
	cmd.Flags().DurationVar(&config.SimnetSlotDuration, "simnet-slot-duration", time.Second, "Configures slot duration in simnet beacon mock.")
	cmd.Flags().BoolVar(&config.SimnetBMockFuzz, "simnet-beacon-mock-fuzz", false, "Configures simnet beaconmock to return fuzzed responses.")
	cmd.Flags().StringVar(&config.TestnetConfig.Name, "testnet-name", "", "Name of the custom test network.")
	cmd.Flags().StringVar(&config.TestnetConfig.GenesisForkVersionHex, "testnet-fork-version", "", "Genesis fork version in hex of the custom test network.")
	cmd.Flags().Uint64Var(&config.TestnetConfig.ChainID, "testnet-chain-id", 0, "Chain ID of the custom test network.")
	cmd.Flags().Int64Var(&config.TestnetConfig.GenesisTimestamp, "testnet-genesis-timestamp", 0, "Genesis timestamp of the custom test network.")

	wrapPreRunE(cmd, func(cmd *cobra.Command, args []string) error {
		if len(config.BeaconNodeAddrs) == 0 && !config.SimnetBMock {
			return errors.New("either flag 'beacon-node-endpoints' or flag 'simnet-beacon-mock=true' must be specified")
		}

		return nil
	})
}

func bindUnsafeRunFlags(cmd *cobra.Command, config *app.Config) {
	cmd.Flags().BoolVar(&config.TestConfig.P2PFuzz, "p2p-fuzz", false, "Configures charon to send fuzzed data via p2p network to its peers.")
}

func bindPrivKeyFlag(cmd *cobra.Command, privKeyFile *string, privkeyLockEnabled *bool) {
	cmd.Flags().StringVar(privKeyFile, "private-key-file", ".charon/charon-enr-private-key", "The path to the charon enr private key file.")
	cmd.Flags().BoolVar(privkeyLockEnabled, "private-key-file-lock", false, "Enables private key locking to prevent multiple instances using the same key.")
}

func bindLogFlags(flags *pflag.FlagSet, config *log.Config) {
	flags.StringVar(&config.Format, "log-format", "console", "Log format; console, logfmt or json")
	flags.StringVar(&config.Level, "log-level", "info", "Log level; debug, info, warn or error")
	flags.StringVar(&config.Color, "log-color", "auto", "Log color; auto, force, disable.")
	flags.StringVar(&config.LogOutputPath, "log-output-path", "", "Path in which to write on-disk logs.")
}

func bindP2PFlags(cmd *cobra.Command, config *p2p.Config) {
	cmd.Flags().StringSliceVar(&config.Relays, "p2p-relays", []string{"https://0.relay.obol.tech", "https://1.relay.obol.tech"}, "Comma-separated list of libp2p relay URLs or multiaddrs.")
	cmd.Flags().StringVar(&config.ExternalIP, "p2p-external-ip", "", "The IP address advertised by libp2p. This may be used to advertise an external IP.")
	cmd.Flags().StringVar(&config.ExternalHost, "p2p-external-hostname", "", "The DNS hostname advertised by libp2p. This may be used to advertise an external DNS.")
	cmd.Flags().StringSliceVar(&config.TCPAddrs, "p2p-tcp-address", nil, "Comma-separated list of listening TCP addresses (ip and port) for libP2P traffic. Empty default doesn't bind to local port therefore only supports outgoing connections.")
	cmd.Flags().BoolVar(&config.DisableReuseport, "p2p-disable-reuseport", false, "Disables TCP port reuse for outgoing libp2p connections.")

	wrapPreRunE(cmd, func(cmd *cobra.Command, args []string) error {
		for _, relay := range config.Relays {
			u, err := url.Parse(relay)
			if err != nil {
				return errors.Wrap(err, "parse relay address", z.Str("address", relay))
			}

			if u.Scheme == "http" {
				log.Warn(cmd.Context(), "Insecure relay address provided, not HTTPS", nil, z.Str("address", relay))
			}
		}

		return nil
	})
}

func bindFeatureFlags(flags *pflag.FlagSet, config *featureset.Config) {
	flags.StringSliceVar(&config.Enabled, "feature-set-enable", nil, "Comma-separated list of features to enable, overriding the default minimum feature set.")
	flags.StringSliceVar(&config.Disabled, "feature-set-disable", nil, "Comma-separated list of features to disable, overriding the default minimum feature set.")
	flags.StringVar(&config.MinStatus, "feature-set", "stable", "Minimum feature set to enable by default: alpha, beta, or stable. Warning: modify at own risk.")
}

// wrapPreRunE wraps the provided preRunE function.
func wrapPreRunE(cmd *cobra.Command, fn func(cmd *cobra.Command, args []string) error) {
	preRunE := cmd.PreRunE // Allow multiple wraps of PreRunE.
	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		err := fn(cmd, args)
		if err != nil {
			return err
		}

		if preRunE != nil {
			return preRunE(cmd, args)
		}

		return nil
	}
}
