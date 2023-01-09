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

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cmd/relay"
)

func newRelayCmd(runFunc func(context.Context, relay.Config) error) *cobra.Command {
	var config relay.Config

	cmd := &cobra.Command{
		Use:   "relay",
		Short: "Start a libp2p relay server",
		Long:  "Starts a libp2p relay that charon nodes can use to bootstrap their p2p cluster",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := log.InitLogger(config.LogConfig); err != nil {
				return err
			}

			printFlags(cmd.Context(), cmd.Flags())

			return runFunc(cmd.Context(), config)
		},
	}

	bindDataDirFlag(cmd.Flags(), &config.DataDir)
	bindRelayFlag(cmd.Flags(), &config)
	bindP2PFlags(cmd, &config.P2PConfig)
	bindLogFlags(cmd.Flags(), &config.LogConfig)
	bindLokiFlags(cmd.Flags(), &config.LogConfig)

	return cmd
}

func newBootnodeCmd(runFunc func(context.Context, relay.Config) error) *cobra.Command {
	var config relay.Config

	cmd := &cobra.Command{
		Use:   "bootnode",
		Short: "Start a discv5 bootnode server. Deprecated, use 'charon relay'",
		Long:  `Starts a discv5 bootnode that charon nodes can use to bootstrap their p2p cluster`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := log.InitLogger(config.LogConfig); err != nil {
				return err
			}

			log.Warn(log.WithTopic(cmd.Context(), "cmd"), "Deprecated 'bootnode' command used, please use 'charon relay' instead", nil)

			printFlags(cmd.Context(), cmd.Flags())

			return runFunc(cmd.Context(), config)
		},
	}

	bindDataDirFlag(cmd.Flags(), &config.DataDir)
	bindBootnodeFlag(cmd.Flags(), &config)
	bindP2PFlags(cmd, &config.P2PConfig)
	bindLogFlags(cmd.Flags(), &config.LogConfig)
	bindLokiFlags(cmd.Flags(), &config.LogConfig)

	return cmd
}

func bindRelayFlag(flags *pflag.FlagSet, config *relay.Config) {
	flags.StringVar(&config.HTTPAddr, "http-address", "127.0.0.1:3640", "Listening address (ip and port) for the relay http server serving runtime ENR.")
	flags.StringVar(&config.MonitoringAddr, "monitoring-address", "127.0.0.1:3620", "Listening address (ip and port) for the prometheus and pprof monitoring http server.")
	flags.BoolVar(&config.AutoP2PKey, "auto-p2pkey", true, "Automatically create a p2pkey (ecdsa private key used for p2p authentication and ENR) if none found in data directory.")
	flags.StringVar(&config.RelayLogLevel, "p2p-relay-loglevel", "", "Libp2p circuit relay log level. E.g., debug, info, warn, error.")

	// Decrease defaults after this has been addressed https://github.com/libp2p/go-libp2p/issues/1713
	flags.IntVar(&config.MaxResPerPeer, "p2p-max-reservations", 512, "Updates max circuit reservations per peer (each valid for 30min)")
	flags.IntVar(&config.MaxConns, "p2p-max-connections", 16384, "Libp2p maximum number of peers that can connect to this relay.")
}

func bindBootnodeFlag(flags *pflag.FlagSet, config *relay.Config) {
	flags.StringVar(&config.HTTPAddr, "bootnode-http-address", "127.0.0.1:3640", "Listening address (ip and port) for the bootnode http server serving runtime ENR.")
	flags.StringVar(&config.MonitoringAddr, "bootnode-monitoring-address", "127.0.0.1:3620", "Listening address (ip and port) for the prometheus and pprof monitoring http server.")
	flags.BoolVar(&config.AutoP2PKey, "auto-p2pkey", true, "Automatically create a p2pkey (ecdsa private key used for p2p authentication and ENR) if none found in data directory.")
	flags.StringVar(&config.RelayLogLevel, "p2p-relay-loglevel", "", "Libp2p circuit relay log level. E.g., debug, info, warn, error.")

	// Decrease defaults after this has been addressed https://github.com/libp2p/go-libp2p/issues/1713
	flags.IntVar(&config.MaxResPerPeer, "max-reservations", 512, "Updates max circuit reservations per peer (each valid for 30min)") // TODO(corver): Align flag name to p2p-max-reservations
	flags.IntVar(&config.MaxConns, "p2p-max-connections", 16384, "Libp2p maximum number of peers that can connect to this bootnode.")
}
