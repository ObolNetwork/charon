// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import "github.com/spf13/cobra"

func newCreateCmd(cmds ...*cobra.Command) *cobra.Command {
	root := &cobra.Command{
		Use:   "create",
		Short: "Create artifacts for a distributed validator cluster",
		Long:  "Create artifacts for a distributed validator cluster. These commands can be used to facilitate the creation of a distributed validator cluster between a group of operators by performing a distributed key generation ceremony, or they can be used to create a local cluster for single operator use cases.",
	}

	root.AddCommand(cmds...)

	return root
}
