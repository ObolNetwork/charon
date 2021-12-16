// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"

	"github.com/obolnetwork/charon/api/server"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/discovery"
	"github.com/obolnetwork/charon/identity"
	"github.com/obolnetwork/charon/internal"
	"github.com/obolnetwork/charon/internal/appctx"
	"github.com/obolnetwork/charon/internal/config"
	"github.com/obolnetwork/charon/p2p"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"
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

// runCharon is the main routine powering the Charon daemon.
func runCharon(_ *cobra.Command, _ []string) {
	// The exit context cancels as soon as the user requests an exit.
	// Note that services may outlive the exit context.
	exitCtx := appctx.InterruptContext(context.Background())
	// The application context cancels as soon as any module raises a fatal error.
	appGroup, appCtx := errgroup.WithContext(exitCtx)

	log.Info().Str("version", internal.ReleaseVersion).Msg("Charon starting")

	// Load known DV clusters.
	manifests, err := cluster.LoadKnownClusters()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load DV clusters")
	}
	log.Info().Msgf("Loaded %d DVs", len(manifests.Clusters()))
	// Create connection gater.
	connGater := p2p.NewConnGaterForClusters(manifests, nil)
	log.Info().Msgf("Connecting to %d unique peers", len(connGater.PeerIDs))

	// Create or retrieve our P2P identity key.
	p2pIdentity := identity.DefaultP2P()
	p2pKey, err := p2pIdentity.Get()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get peer ID")
	}
	// Create P2P client.
	p2pConfig := p2p.DefaultConfig()
	node, err := p2p.NewNode(appCtx, p2pConfig, p2pKey, connGater)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to start P2P")
	}

	// Create peer discovery.
	discoveryConfig := discovery.DefaultConfig(p2pConfig)
	peerDB, err := discovery.NewPeerDB(discoveryConfig, p2pConfig, p2pKey)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to open peer DB")
	}
	discoveryNode := discovery.NewNode(discoveryConfig, peerDB, p2pKey)
	appGroup.Go(discoveryNode.Listen)

	// Create internal API handler.
	handler := &server.Handler{
		PeerDB: peerDB,
		Node:   node,
	}
	// Start internal API server.
	if intAddr := viper.GetString(config.KeyAPI); intAddr != "" {
		appGroup.Go(func() error {
			err := server.Run(appCtx, server.Options{
				Addr:    intAddr,
				Handler: handler,
				Log:     log.With().Str("component", "api").Logger(),
			})
			return err
		})
	}

	// Wait for services to exit gracefully or fail.
	if err := appGroup.Wait(); err != nil {
		log.Error().Err(err).Msg("Fatal error")
	}
}
