// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"github.com/spf13/cobra"
)

func newEditCmd(cmds ...*cobra.Command) *cobra.Command {
	root := &cobra.Command{
		Use:   "edit",
		Short: "Subcommands provide functionality to modify existing cluster configurations",
		Long:  "Subcommands allow users to modify existing distributed validator cluster configurations, such as adding, removing or replacing operators.",
	}

	root.AddCommand(cmds...)

	return root
}
