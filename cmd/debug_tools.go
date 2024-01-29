// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"github.com/spf13/cobra"
)

// bindDebugMonitoringFlags binds Prometheus monitoring and debug address CLI flags. The debug address defaults to an empty address.
func bindDebugMonitoringFlags(cmd *cobra.Command, monitorAddr, debugAddr *string, defaultMonitorAddr string) {
	cmd.Flags().StringVar(monitorAddr, "monitoring-address", defaultMonitorAddr, "Listening address (ip and port) for the monitoring API (prometheus).")
	cmd.Flags().StringVar(debugAddr, "debug-address", "", "Listening address (ip and port) for the pprof and QBFT debug API. It is not enabled by default.")
}
