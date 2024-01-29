// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import "github.com/spf13/cobra"

func newUnsafeCmd(cmds ...*cobra.Command) *cobra.Command {
	unsafe := &cobra.Command{
		Use:   "unsafe",
		Short: "Unsafe subcommands provides regular charon commands for testing purposes",
		Long: "Unsafe subcommands is a group of subcommands that includes both normal and test flags. " +
			"It is intended for internal testing of the Charon client and should be used with caution.",
	}

	// Mark unsafe command as hidden for internal testing purposes.
	unsafe.Hidden = true
	unsafe.AddCommand(cmds...)

	return unsafe
}
