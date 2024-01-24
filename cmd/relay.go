// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"

	libp2plog "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"

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
	bindRelayFlag(cmd, &config)
	bindDebugMonitoringFlags(cmd, &config.MonitoringAddr, &config.DebugAddr, "")
	bindP2PFlags(cmd, &config.P2PConfig)
	bindLogFlags(cmd.Flags(), &config.LogConfig)
	bindLokiFlags(cmd.Flags(), &config.LogConfig)

	return cmd
}

func bindRelayFlag(cmd *cobra.Command, config *relay.Config) {
	cmd.Flags().StringVar(&config.HTTPAddr, "http-address", "127.0.0.1:3640", "Listening address (ip and port) for the relay http server serving runtime ENR.")
	cmd.Flags().BoolVar(&config.AutoP2PKey, "auto-p2pkey", true, "Automatically create a p2pkey (secp256k1 private key used for p2p authentication and ENR) if none found in data directory.")
	cmd.Flags().StringVar(&config.RelayLogLevel, "p2p-relay-loglevel", "", "Libp2p circuit relay log level. E.g., debug, info, warn, error.")

	// Decrease defaults after this has been addressed https://github.com/libp2p/go-libp2p/issues/1713
	cmd.Flags().IntVar(&config.MaxResPerPeer, "p2p-max-reservations", 512, "Updates max circuit reservations per peer (each valid for 30min)")
	cmd.Flags().IntVar(&config.MaxConns, "p2p-max-connections", 16384, "Libp2p maximum number of peers that can connect to this relay.")

	var advertisePriv bool
	cmd.Flags().BoolVar(&advertisePriv, "p2p-advertise-private-addresses", false, "Enable advertising of libp2p auto-detected private addresses. This doesn't affect manually provided p2p-external-ip/hostname.")

	wrapPreRunE(cmd, func(cmd *cobra.Command, args []string) error {
		// Invert p2p-advertise-private-addresses flag boolean:
		// -- Do not ADVERTISE private addresses by default in the binary.
		// -- Do not FILTER private addresses in unit tests.
		config.FilterPrivAddrs = !advertisePriv

		return nil
	})
}
