// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"github.com/spf13/cobra"
)

func newAlphaCmd(cmds ...*cobra.Command) *cobra.Command {
	root := &cobra.Command{
		Use:   "alpha",
		Short: "Alpha subcommands provide early access to in-development features",
		Long:  `Alpha subcommands represent features that are currently under development. They're not yet released for general use, but offer a glimpse into future functionalities planned for the distributed cluster system.`,
	}

	root.AddCommand(cmds...)

	return root
}
