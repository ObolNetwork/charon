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

	libp2plog "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/p2p"
)

func newRunCmd(runFunc func(context.Context, app.Config) error) *cobra.Command {
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

	bindPrivKeyFlag(cmd, &conf.PrivKeyFile)
	bindRunFlags(cmd, &conf)
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
	cmd.Flags().StringVar(&config.LockFile, "lock-file", ".charon/cluster-lock.json", "The path to the cluster lock file defining distributed validator cluster.")
	cmd.Flags().StringSliceVar(&config.BeaconNodeAddrs, "beacon-node-endpoints", nil, "Comma separated list of one or more beacon node endpoint URLs.")
	cmd.Flags().StringVar(&config.ValidatorAPIAddr, "validator-api-address", "127.0.0.1:3600", "Listening address (ip and port) for validator-facing traffic proxying the beacon-node API.")
	cmd.Flags().StringVar(&config.MonitoringAddr, "monitoring-address", "127.0.0.1:3620", "Listening address (ip and port) for the monitoring API (prometheus, pprof).")
	cmd.Flags().StringVar(&config.JaegerAddr, "jaeger-address", "", "Listening address for jaeger tracing.")
	cmd.Flags().StringVar(&config.JaegerService, "jaeger-service", "charon", "Service name used for jaeger tracing.")
	cmd.Flags().BoolVar(&config.SimnetBMock, "simnet-beacon-mock", false, "Enables an internal mock beacon node for running a simnet.")
	cmd.Flags().BoolVar(&config.SimnetVMock, "simnet-validator-mock", false, "Enables an internal mock validator client when running a simnet. Requires simnet-beacon-mock.")
	cmd.Flags().StringVar(&config.SimnetValidatorKeysDir, "simnet-validator-keys-dir", ".charon/validator_keys", "The directory containing the simnet validator key shares.")
	cmd.Flags().BoolVar(&config.BuilderAPI, "builder-api", false, "Enables the builder api. Will only produce builder blocks. Builder API must also be enabled on the validator client. Beacon node must be connected to a builder-relay to access the builder network.")
	cmd.Flags().BoolVar(&config.SyntheticBlockProposals, "synthetic-block-proposals", false, "Enables additional synthetic block proposal duties. Used for testing of rare duties.")

	wrapPreRunE(cmd, func(cmd *cobra.Command, args []string) error {
		if len(config.BeaconNodeAddrs) == 0 && !config.SimnetBMock {
			return errors.New("either flag 'beacon-node-endpoints' or flag 'simnet-beacon-mock=true' must be specified")
		}

		return nil
	})
}

func bindPrivKeyFlag(cmd *cobra.Command, privKeyFile *string) {
	var dataDir string

	cmd.Flags().StringVar(&dataDir, "data-dir", "", "Deprecated, please use 'private-key-file'.")
	cmd.Flags().StringVar(privKeyFile, "private-key-file", ".charon/charon-enr-private-key", "The path to the charon enr private key file.")

	wrapPreRunE(cmd, func(cmd *cobra.Command, args []string) error {
		ctx := log.WithTopic(cmd.Context(), "cmd")
		if dataDir != "" {
			log.Warn(ctx, "Deprecated flag 'data-dir' used, please use new flag 'private-key-file'.", nil)
		}

		if _, err := os.Open(*privKeyFile); err == nil { //nolint:revive
			// Ignore data-dir since priv key file is present
		} else if _, err := os.Open(p2p.KeyPath(dataDir)); err == nil { //nolint:revive
			*privKeyFile = p2p.KeyPath(dataDir)
		} else {
			return errors.New("charon enr private key file not found in either `data-dir` or `private-key-file`")
		}

		return nil
	})
}

func bindLogFlags(flags *pflag.FlagSet, config *log.Config) {
	flags.StringVar(&config.Format, "log-format", "console", "Log format; console, logfmt or json")
	flags.StringVar(&config.Level, "log-level", "info", "Log level; debug, info, warn or error")
}

func bindP2PFlags(cmd *cobra.Command, config *p2p.Config) {
	var relays []string
	cmd.Flags().StringSliceVar(&relays, "p2p-relays", []string{"https://0.relay.obol.tech/enr", "http://bootnode.lb.gcp.obol.tech:3640/enr"}, "Comma-separated list of libp2p relay URLs or ENRs.")
	cmd.Flags().StringSliceVar(&config.UDPBootnodes, "p2p-bootnodes", nil, "Comma-separated list of discv5 bootnode URLs or ENRs. Deprecated, use p2p-relays flag.")
	cmd.Flags().BoolVar(&config.BootnodeRelay, "p2p-bootnode-relay", true, "Enables using bootnodes as libp2p circuit relays. Useful if some charon nodes are not publicly accessible. Deprecated, should always be enabled.")
	cmd.Flags().BoolVar(&config.UDPBootLock, "p2p-bootnodes-from-lockfile", false, "Enables using cluster lock ENRs as discv5 bootnodes. Allows skipping explicit bootnodes if key generation ceremony included correct IPs. Discv5 is deprecated, use relay discovery.")
	cmd.Flags().StringVar(&config.UDPAddr, "p2p-udp-address", "", "Listening UDP address (ip and port) for discv5 discovery. Empty default disables discv5 discovery. Discv5 is deprecated, use relay discovery.")
	cmd.Flags().StringVar(&config.ExternalIP, "p2p-external-ip", "", "The IP address advertised by libp2p. This may be used to advertise an external IP.")
	cmd.Flags().StringVar(&config.ExternalHost, "p2p-external-hostname", "", "The DNS hostname advertised by libp2p. This may be used to advertise an external DNS.")
	cmd.Flags().StringSliceVar(&config.TCPAddrs, "p2p-tcp-address", nil, "Comma-separated list of listening TCP addresses (ip and port) for libP2P traffic. Empty default doesn't bind to local port therefore only supports outgoing connections.")
	cmd.Flags().StringVar(&config.Allowlist, "p2p-allowlist", "", "Comma-separated list of CIDR subnets for allowing only certain peer connections. Example: 192.168.0.0/16 would permit connections to peers on your local network only. The default is to accept all connections.")
	cmd.Flags().StringVar(&config.Denylist, "p2p-denylist", "", "Comma-separated list of CIDR subnets for disallowing certain peer connections. Example: 192.168.0.0/16 would disallow connections to peers on your local network. The default is to accept all connections.")
	cmd.Flags().BoolVar(&config.DisableReuseport, "p2p-disable-reuseport", false, "Disables TCP port reuse for outgoing libp2p connections.")

	wrapPreRunE(cmd, func(cmd *cobra.Command, args []string) error {
		ctx := log.WithTopic(cmd.Context(), "cmd")

		if config.UDPAddr == "" && !config.BootnodeRelay && !config.UDPBootLock {
			return errors.New("node undiscoverable with the provided settings, please configure any one of `p2p-udp-address`, `p2p-bootnode-relay` or `p2p-bootnodes-from-lockfile`")
		}

		if !config.BootnodeRelay {
			log.Warn(ctx, "Deprecated flag 'p2p-bootnode-relay' disabled, it will always be enabled from the next release", nil)
		}

		if config.UDPBootLock {
			log.Warn(ctx, "Deprecated flag 'p2p-bootnodes-from-lockfile' used, it will be removed in the next release along with discv5 peer discovery", nil)
		}

		if config.UDPAddr != "" {
			log.Warn(ctx, "Deprecated flag 'p2p-udp-address' used, discv5 peer discovery will be removed in the next release", nil)
		}

		if len(config.UDPBootnodes) > 0 {
			log.Warn(ctx, "Deprecated flag 'p2p-bootnodes' used, please use 'p2p-relays'", nil)
		}

		config.UDPBootnodes = append(config.UDPBootnodes, relays...)

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
