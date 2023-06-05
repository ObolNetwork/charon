// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"github.com/spf13/cobra"
)

func newAlphaCmd(cmds ...*cobra.Command) *cobra.Command {
	root := &cobra.Command{
		Use:   "alpha",
		Short: "Alpha charon subcommands are work-in-progress features that are not released to the users.",
		Long:  "Alpha charon subcommands are work-in-progress features that are not released to the users. They are future functionalities for a charon distributed cluster.",
	}

	root.AddCommand(cmds...)

	return root
}
