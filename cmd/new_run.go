// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"os"
	"os/signal"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/obolnetwork/charon/runner"
)

func newRunCmd() *cobra.Command {
	var conf runner.Config

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Runs the Charon middleware",
		Long:  "Starts the long-running Charon middleware process to perform distributed validator duties.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer cancel()

			return runner.Run(ctx, conf)
		},
	}

	bindRunFlags(cmd.Flags(), &conf)

	return cmd
}

func bindRunFlags(flags *pflag.FlagSet, config *runner.Config) {
	flags.StringVar(&config.DataDir, "data-dir", "./charon/data", "The directory where charon will store all its internal data")
	flags.StringVar(&config.ClusterDir, "cluster-file", "./charon/manifest.json", "The filepath to the manifest file defining distributed validator cluster")
	flags.StringVar(&config.BeaconNodeAddr, "beacon-node-endpoint", "http://localhost/", "Beacon node endpoint URL")
	flags.StringVar(&config.ValidatorAPIAddr, "validator-api-address", "http://0.0.0.0", "Listening address for validator-facing traffic proxying the beacon-node API")
	flags.IntVar(&config.ValidatorAPIPort, "validator-api-port", 3500, "Listening port for validator-facing traffic proxying the beacon-node API.")
	flags.StringVar(&config.MonitoringAddr, "monitoring-address", "http://0.0.0.0", "Listening address for the monitoring API (prometheus, pprof)")
	flags.IntVar(&config.MonitoringPort, "monitoring-port", 8088, "Listening port for monitoring API (prometheus, pprof)")
	flags.StringVar(&config.JaegerAddr, "jaegar-address", "", "Listening address for Jaegar tracing")
	flags.IntVar(&config.Discovery.ListenAddr.Port, "p2p-udp-port", 30309, "Listening UDP port for Discovery v5 discovery")
}
