// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package main

import (
	"context"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/obolnetwork/charon/testutil/promrated"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cobra.CheckErr(newRootCmd(promrated.Run).ExecuteContext(ctx))
}

func newRootCmd(runFunc func(context.Context, promrated.Config) error) *cobra.Command {
	var config promrated.Config

	root := &cobra.Command{
		Use:   "promrated",
		Short: "Starts a promrated server",
		Long:  `Starts a promrated server that polls rated and makes metrics available to prometheus`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFunc(cmd.Context(), config)
		},
	}

	bindPromratedFlag(root.Flags(), &config)

	return root
}

func bindPromratedFlag(flags *pflag.FlagSet, config *promrated.Config) {
	flags.StringVar(&config.RatedEndpoint, "rated-endpoint", "https://api.rated.network", "Rated API endpoint to poll for validator metrics.")
	flags.StringVar(&config.RatedAuth, "rated-auth-token", "token", "[REQUIRED] Token for Rated API.")
	flags.StringVar(&config.MonitoringAddr, "monitoring-address", "127.0.0.1:9200", "Listening address (ip and port) for the prometheus monitoring http server.")
	flags.StringVar(&config.PromAuth, "prom-auth-token", "token", "[REQUIRED] Token for VMetrics Promtetheus API.")
	flags.StringSliceVar(&config.Networks, "networks", nil, "Comma separated list of one or networks to monitor.")
	flags.StringSliceVar(&config.NodeOperators, "node-operators", nil, "Comma separated list of one or node operators to monitor.")
}
