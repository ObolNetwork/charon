package cmd

import (
	"context"

	"github.com/obolnetwork/charon/p2p"
	"github.com/spf13/cobra"
)

var runCmd = cobra.Command{
	Use:   "run",
	Short: "Runs the Charon middleware",
	Long:  "Starts the long-running Charon middleware process to perform distributed validator duties.",
	Args:  cobra.NoArgs,
	Run:   runCharon,
}

func init() {
	rootCmd.AddCommand(&runCmd)
}

func runCharon(_ *cobra.Command, _ []string) {
	// Create P2P client.
	ctx := context.Background()
	p2pConfig := p2p.DefaultConfig()
	node, err := p2p.NewNode(ctx, p2pConfig)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to start P2P")
	}
	_ = node
	// TODO for now, Charon has nothing to do after starting the node
	select {}
}
