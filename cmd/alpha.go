// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"github.com/spf13/cobra"
)

func newAlphaCmd(cmds ...*cobra.Command) *cobra.Command {
	root := &cobra.Command{
		Use:   "alpha",
		Short: "Alpha subcommands provide early access to in-development features",
		Long:  "Alpha subcommands represent features that are currently under development. They're not yet recommended for production use, may undergo breaking changes in this phase, but offer early access to upcoming features for the distributed validator cluster.",
	}

	root.AddCommand(cmds...)

	return root
}
