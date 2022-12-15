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
	flags.StringVar(&config.MonitoringAddr, "monitoring-address", "127.0.0.1:9100", "Listening address (ip and port) for the prometheus monitoring http server.")
	flags.StringVar(&config.PromEndpoint, "prom-endpoint", "https://vm.monitoring.gcp.obol.tech/query", "Endpoint for VMetrics Prometheus API.")
	flags.StringVar(&config.PromAuth, "prom-auth-token", "token", "[REQUIRED] Token for VMetrics Promtetheus API.")
}
