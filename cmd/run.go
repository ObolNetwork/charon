package cmd

import (
	"context"

	"github.com/obolnetwork/charon/api/server"
	"github.com/obolnetwork/charon/discovery"
	"github.com/obolnetwork/charon/identity"
	"github.com/obolnetwork/charon/internal"
	"github.com/obolnetwork/charon/internal/config"
	"github.com/obolnetwork/charon/p2p"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
	ctx := context.Background()

	log.Info().Str("version", internal.ReleaseVersion).Msg("Charon starting")

	// Create P2P client.
	p2pConfig := p2p.DefaultConfig()
	node, err := p2p.NewNode(ctx, p2pConfig)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to start P2P")
	}
	_ = node
	// Create peer discovery.
	p2pIdentity := identity.DefaultP2P() // TODO this should only be called once
	p2pKey, err := p2pIdentity.Get()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get peer ID")
	}
	peerDB, err := discovery.NewPeerDB(viper.GetString(config.KeyNodeDB), p2pConfig, p2pKey)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to open peer DB")
	}
	// Create internal API handler.
	handler := &server.Handler{
		PeerDB: peerDB,
		Node:   node,
	}
	// Start internal API server.
	if intAddr := viper.GetString(config.KeyAPI); intAddr != "" {
		go func() {
			err := server.Run(ctx, server.Options{
				Addr:    intAddr,
				Handler: handler,
				Log:     log.With().Str("component", "api").Logger(),
			})
			if err != nil {
				log.Error().Err(err).Msg("Internal HTTP API failed")
			}
		}()
	}
	// TODO for now, Charon has nothing to do after starting the node
	select {}
}
