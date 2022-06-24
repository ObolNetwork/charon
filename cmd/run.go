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
			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer cancel()

			return runFunc(ctx, conf)
		},
	}

	bindRunFlags(cmd.Flags(), &conf)
	bindDataDirFlag(cmd.Flags(), &conf.DataDir)
	bindP2PFlags(cmd.Flags(), &conf.P2P)
	bindLogFlags(cmd.Flags(), &conf.Log)
	bindFeatureFlags(cmd.Flags(), &conf.Feature)

	return cmd
}

func bindRunFlags(flags *pflag.FlagSet, config *app.Config) {
	flags.StringVar(&config.LockFile, "lock-file", ".charon/cluster/cluster-lock.json", "The path to the cluster lock file defining distributed validator cluster")
	flags.StringVar(&config.BeaconNodeAddr, "beacon-node-endpoint", "http://localhost/", "Beacon node endpoint URL")
	flags.StringVar(&config.ValidatorAPIAddr, "validator-api-address", "127.0.0.1:3600", "Listening address (ip and port) for validator-facing traffic proxying the beacon-node API")
	flags.StringVar(&config.MonitoringAddr, "monitoring-address", "127.0.0.1:3620", "Listening address (ip and port) for the monitoring API (prometheus, pprof)")
	flags.StringVar(&config.JaegerAddr, "jaeger-address", "", "Listening address for jaeger tracing")
	flags.StringVar(&config.JaegerService, "jaeger-service", "charon", "Service name used for jaeger tracing")
	flags.BoolVar(&config.SimnetBMock, "simnet-beacon-mock", false, "Enables an internal mock beacon node for running a simnet.")
	flags.BoolVar(&config.SimnetVMock, "simnet-validator-mock", false, "Enables an internal mock validator client when running a simnet. Requires simnet-beacon-mock.")
}

func bindLogFlags(flags *pflag.FlagSet, config *log.Config) {
	flags.StringVar(&config.Format, "log-format", "console", "Log format; console, logfmt or json")
	flags.StringVar(&config.Level, "log-level", "info", "Log level; debug, info, warn or error")
}

func bindDataDirFlag(flags *pflag.FlagSet, dataDir *string) {
	flags.StringVar(dataDir, "data-dir", ".charon", "The directory where charon will store all its internal data")
}

func bindP2PFlags(flags *pflag.FlagSet, config *p2p.Config) {
	flags.StringSliceVar(&config.UDPBootnodes, "p2p-bootnodes", []string{"http://bootnode.gcp.obol.tech:16000/enr"}, "Comma-separated list of discv5 bootnode URLs or ENRs.")
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
