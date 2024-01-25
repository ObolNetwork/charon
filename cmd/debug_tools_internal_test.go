// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app"
)

func genTestCmd(t *testing.T, f func(config app.Config)) *cobra.Command {
	t.Helper()

	var conf app.Config

	cmd := &cobra.Command{
		Use:   "test",
		Short: "test",
	}

	cmd.Run = func(cmd *cobra.Command, args []string) {
		f(conf)
	}

	bindDebugMonitoringFlags(cmd, &conf.MonitoringAddr, &conf.DebugAddr, "")

	return cmd
}

func Test_bindDebugMonitoringFlags(t *testing.T) {
	cmd := &cobra.Command{
		Use: "testcmd",
	}

	t.Run("both present", func(t *testing.T) {
		var (
			mAddr = "127.0.0.1:9999"
			dAddr = "127.0.0.1:8888"
		)

		cmd.ResetCommands()

		testCmd := genTestCmd(t, func(config app.Config) {
			require.Equal(t, mAddr, config.MonitoringAddr)
			require.Equal(t, dAddr, config.DebugAddr)
		})

		cmd.AddCommand(testCmd)

		cmd.SetArgs([]string{
			"test",
			"--monitoring-address",
			mAddr,
			"--debug-address",
			dAddr,
		})

		require.NoError(t, cmd.Execute())
	})

	t.Run("only monitor", func(t *testing.T) {
		var (
			mAddr = "127.0.0.1:9999"
			dAddr = ""
		)
		cmd.ResetCommands()

		testCmd := genTestCmd(t, func(config app.Config) {
			require.Equal(t, mAddr, config.MonitoringAddr)
			require.Equal(t, dAddr, config.DebugAddr)
		})

		cmd.AddCommand(testCmd)

		cmd.SetArgs([]string{
			"test",
			"--monitoring-address",
			mAddr,
		})

		require.NoError(t, cmd.Execute())
	})

	t.Run("only debug", func(t *testing.T) {
		var (
			mAddr = ""
			dAddr = "127.0.0.1:8888"
		)

		cmd.ResetCommands()

		testCmd := genTestCmd(t, func(config app.Config) {
			require.Equal(t, mAddr, config.MonitoringAddr)
			require.Equal(t, dAddr, config.DebugAddr)
		})

		cmd.AddCommand(testCmd)

		cmd.SetArgs([]string{
			"test",
			"--debug-address",
			dAddr,
		})

		require.NoError(t, cmd.Execute())
	})
}
