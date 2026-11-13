// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/log"
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

// logProposerConfigOutput tells the operator the proposer config re-signed for the new lock replaces the current one.
func logProposerConfigOutput(ctx context.Context, outputDir string) {
	path := filepath.Join(outputDir, "vc-config", "proposer-config.json")

	log.Info(ctx, "The proposer config was re-signed for the new lock: "+path+", it replaces your current vc-config/proposer-config.json")
}
