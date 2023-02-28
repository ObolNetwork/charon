// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"

	libp2plog "github.com/ipfs/go-log/v2"
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
			libp2plog.SetPrimaryCore(log.LoggerCore()) // Set libp2p logger to use charon logger

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

func bindRelayFlag(flags *pflag.FlagSet, config *relay.Config) {
	flags.StringVar(&config.HTTPAddr, "http-address", "127.0.0.1:3640", "Listening address (ip and port) for the relay http server serving runtime ENR.")
	flags.StringVar(&config.MonitoringAddr, "monitoring-address", "127.0.0.1:3620", "Listening address (ip and port) for the prometheus and pprof monitoring http server.")
	flags.BoolVar(&config.AutoP2PKey, "auto-p2pkey", true, "Automatically create a p2pkey (secp256k1 private key used for p2p authentication and ENR) if none found in data directory.")
	flags.StringVar(&config.RelayLogLevel, "p2p-relay-loglevel", "", "Libp2p circuit relay log level. E.g., debug, info, warn, error.")

	// Decrease defaults after this has been addressed https://github.com/libp2p/go-libp2p/issues/1713
	flags.IntVar(&config.MaxResPerPeer, "p2p-max-reservations", 512, "Updates max circuit reservations per peer (each valid for 30min)")
	flags.IntVar(&config.MaxConns, "p2p-max-connections", 16384, "Libp2p maximum number of peers that can connect to this relay.")
}
