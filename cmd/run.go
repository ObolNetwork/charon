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
	"context"
	"os"
	"os/signal"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/p2p"
)

func newRunCmd(runFunc func(context.Context, app.Config) error) *cobra.Command {
	var conf app.Config

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the charon middleware client",
		Long:  "Starts the long-running Charon middleware process to perform distributed validator duties.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer cancel()

			return runFunc(ctx, conf)
		},
	}

	bindPrivKeyFlag(cmd, &conf.DataDir, &conf.PrivKeyFile)
	bindRunFlags(cmd, &conf)
	bindNoVerifyFlag(cmd.Flags(), &conf.NoVerify)
	bindP2PFlags(cmd.Flags(), &conf.P2P)
	bindLogFlags(cmd.Flags(), &conf.Log)
	bindFeatureFlags(cmd.Flags(), &conf.Feature)

	return cmd
}

func bindNoVerifyFlag(flags *pflag.FlagSet, config *bool) {
	flags.BoolVar(config, "no-verify", false, "Disables cluster definition and lock file verification.")
}

func bindRunFlags(cmd *cobra.Command, config *app.Config) {
	var beaconNodeAddr string
	cmd.Flags().StringVar(&config.LockFile, "lock-file", ".charon/cluster-lock.json", "The path to the cluster lock file defining distributed validator cluster.")
	cmd.Flags().StringVar(&beaconNodeAddr, "beacon-node-endpoint", "", "Beacon node endpoint URL. Deprecated, please use beacon-node-endpoints.")
	cmd.Flags().StringSliceVar(&config.BeaconNodeAddrs, "beacon-node-endpoints", nil, "Comma separated list of one or more beacon node endpoint URLs.")
	cmd.Flags().StringVar(&config.ValidatorAPIAddr, "validator-api-address", "127.0.0.1:3600", "Listening address (ip and port) for validator-facing traffic proxying the beacon-node API.")
	cmd.Flags().StringVar(&config.MonitoringAddr, "monitoring-address", "127.0.0.1:3620", "Listening address (ip and port) for the monitoring API (prometheus, pprof).")
	cmd.Flags().StringVar(&config.JaegerAddr, "jaeger-address", "", "Listening address for jaeger tracing.")
	cmd.Flags().StringVar(&config.JaegerService, "jaeger-service", "charon", "Service name used for jaeger tracing.")
	cmd.Flags().BoolVar(&config.SimnetBMock, "simnet-beacon-mock", false, "Enables an internal mock beacon node for running a simnet.")
	cmd.Flags().BoolVar(&config.SimnetVMock, "simnet-validator-mock", false, "Enables an internal mock validator client when running a simnet. Requires simnet-beacon-mock.")
	cmd.Flags().StringVar(&config.SimnetValidatorKeys, "simnet-validator-keys", ".charon/validator_keys", "The directory containing the simnet validator key shares.")
	cmd.Flags().BoolVar(&config.BuilderAPI, "builder-api", false, "Enables the builder api. Will only produce builder blocks. Builder API must also be enabled on the validator client. Beacon node must be connected to a builder-relay to access the builder network.")

	preRunE := cmd.PreRunE // Allow multiple wraps of PreRunE.
	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		ctx := log.WithTopic(cmd.Context(), "cmd")
		if beaconNodeAddr != "" {
			log.Warn(ctx, "Deprecated flag 'beacon-node-endpoint' used, please use new flag 'beacon-node-endpoints'", nil)
			config.BeaconNodeAddrs = []string{beaconNodeAddr}
		} else if beaconNodeAddr != "" && len(config.BeaconNodeAddrs) > 0 {
			log.Warn(ctx, "Deprecated flag 'beacon-node-endpoint' ignored since new flag 'beacon-node-endpoints' takes precedence",
				nil, z.Str("beacon-node-endpoint", beaconNodeAddr), z.Any("beacon-node-endpoints", config.BeaconNodeAddrs))
		} else if len(config.BeaconNodeAddrs) == 0 && !config.SimnetBMock {
			return errors.New("either flag 'beacon-node-endpoints' or flag 'simnet-beacon-mock=true' must be specified")
			// TODO(corver): Use MarkFlagsRequiredTogether once beacon-node-endpoint is removed.
		}

		if preRunE != nil {
			return preRunE(cmd, args)
		}

		return nil
	}
}

func bindPrivKeyFlag(cmd *cobra.Command, dataDir, privKeyFile *string) { //nolint:gocognit
	charonEnrPrivKey := ".charon/charon-enr-private-key"

	cmd.Flags().StringVar(dataDir, "data-dir", "", "The directory where charon stores all its internal data. Deprecated.")
	cmd.Flags().StringVar(privKeyFile, "private-key", charonEnrPrivKey, "The path to the charon enr private key.")

	preRunE := cmd.PreRunE // Allow multiple wraps of PreRunE.
	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		ctx := log.WithTopic(cmd.Context(), "cmd")
		if *dataDir != "" {
			log.Warn(ctx, "Deprecated flag 'data-dir' used, please use new flag 'private-key'.", nil)
		}

		// --data-dir absent but --private-key present
		if *dataDir == "" && *privKeyFile != charonEnrPrivKey {
			if _, err := os.Open(*privKeyFile); errors.Is(err, os.ErrNotExist) {
				return errors.New("private key file doesn't exist")
			}
		}

		// --data-dir present but --private-key absent
		if *dataDir != "" && *privKeyFile == charonEnrPrivKey {
			if _, err := os.Open(p2p.KeyPath(*dataDir)); errors.Is(err, os.ErrNotExist) {
				return errors.New("private key file doesn't exist")
			}
			*privKeyFile = p2p.KeyPath(*dataDir)

			return nil
		}

		// both --data-dir AND --private-key absent
		if *dataDir == "" && *privKeyFile == charonEnrPrivKey {
			if _, err := os.Open(*privKeyFile); errors.Is(err, os.ErrNotExist) {
				return errors.New("private key file doesn't exist")
			}

			return nil
		}

		// both --data-dir AND --private-key present
		if *dataDir != "" && *privKeyFile != charonEnrPrivKey {
			if _, err := os.Open(*privKeyFile); errors.Is(err, os.ErrNotExist) { // private-key file doesn't exist
				if _, err := os.Open(*dataDir); errors.Is(err, os.ErrNotExist) { // data-dir/charon-enr-private-key doesn't exist
					return errors.New("private-key file doesn't exist")
				}
				*privKeyFile = p2p.KeyPath(*dataDir)
			}
		}

		if preRunE != nil {
			return preRunE(cmd, args)
		}

		return nil
	}
}

func bindLogFlags(flags *pflag.FlagSet, config *log.Config) {
	flags.StringVar(&config.Format, "log-format", "console", "Log format; console, logfmt or json")
	flags.StringVar(&config.Level, "log-level", "info", "Log level; debug, info, warn or error")
}

func bindDataDirFlag(cmd *cobra.Command, dataDir *string) {
	cmd.Flags().StringVar(dataDir, "data-dir", "", "The directory where charon stores all its internal data. Deprecated.")

	preRunE := cmd.PreRunE // Allow multiple wraps of PreRunE.
	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		ctx := log.WithTopic(cmd.Context(), "cmd")
		if *dataDir != "" {
			log.Warn(ctx, "Deprecated flag 'data-dir'. Explicitly specify 'lock-file' for cluster-lock or 'private-key' for charon-enr-private-key.", nil)
		}

		if preRunE != nil {
			return preRunE(cmd, args)
		}

		return nil
	}
}

func bindP2PFlags(flags *pflag.FlagSet, config *p2p.Config) {
	flags.StringSliceVar(&config.UDPBootnodes, "p2p-bootnodes", []string{"http://bootnode.lb.gcp.obol.tech:3640/enr"}, "Comma-separated list of discv5 bootnode URLs or ENRs.")
	flags.BoolVar(&config.BootnodeRelay, "p2p-bootnode-relay", false, "Enables using bootnodes as libp2p circuit relays. Useful if some charon nodes are not have publicly accessible.")
	flags.BoolVar(&config.UDPBootLock, "p2p-bootnodes-from-lockfile", false, "Enables using cluster lock ENRs as discv5 bootnodes. Allows skipping explicit bootnodes if key generation ceremony included correct IPs.")
	flags.StringVar(&config.UDPAddr, "p2p-udp-address", "127.0.0.1:3630", "Listening UDP address (ip and port) for discv5 discovery.")
	flags.StringVar(&config.ExternalIP, "p2p-external-ip", "", "The IP address advertised by libp2p. This may be used to advertise an external IP.")
	flags.StringVar(&config.ExternalHost, "p2p-external-hostname", "", "The DNS hostname advertised by libp2p. This may be used to advertise an external DNS.")
	flags.StringSliceVar(&config.TCPAddrs, "p2p-tcp-address", []string{"127.0.0.1:3610"}, "Comma-separated list of listening TCP addresses (ip and port) for libP2P traffic.")
	flags.StringVar(&config.Allowlist, "p2p-allowlist", "", "Comma-separated list of CIDR subnets for allowing only certain peer connections. Example: 192.168.0.0/16 would permit connections to peers on your local network only. The default is to accept all connections.")
	flags.StringVar(&config.Denylist, "p2p-denylist", "", "Comma-separated list of CIDR subnets for disallowing certain peer connections. Example: 192.168.0.0/16 would disallow connections to peers on your local network. The default is to accept all connections.")
}

func bindFeatureFlags(flags *pflag.FlagSet, config *featureset.Config) {
	flags.StringSliceVar(&config.Enabled, "feature-set-enable", nil, "Comma-separated list of features to enable, overriding the default minimum feature set.")
	flags.StringSliceVar(&config.Disabled, "feature-set-disable", nil, "Comma-separated list of features to disable, overriding the default minimum feature set.")
	flags.StringVar(&config.MinStatus, "feature-set", "stable", "Minimum feature set to enable by default: alpha, beta, or stable. Warning: modify at own risk.")
}
