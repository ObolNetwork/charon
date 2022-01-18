package runner

import (
	"context"
	"fmt"
	"github.com/obolnetwork/charon/api/server"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/discovery"
	"github.com/obolnetwork/charon/identity"
	"github.com/obolnetwork/charon/internal"
	"github.com/obolnetwork/charon/p2p"
	zerologger "github.com/rs/zerolog/log"
	"path"
	"time"
)

// log is a convenience handle to the global logger.
var log = zerologger.Logger

const (
	nodekeyFile = "nodekey"
)

type Config struct {
	Discovery         discovery.Config
	ClusterDir        string
	DataDir           string
	MonitoringAddress string
}

// Run is the entrypoint for running a charon DVC instance.
// All processes and their dependencies are constructed and then started.
// Graceful shutdown is triggered on first process error or when the shutdown context is cancelled.
func Run(shutdownCtx context.Context, conf Config) error {
	nodekey := path.Join(conf.DataDir, nodekeyFile)

	log.Info().Str("version", internal.ReleaseVersion).Msg("Charon starting")

	// Construct processes and their dependencies

	p2pKey, err := identity.P2PStore{KeyPath: nodekey}.Get()
	if err != nil {
		return fmt.Errorf("load or create peer ID: %w", err)
	}

	peerDB, err := discovery.NewPeerDB(&conf.Discovery, conf.Discovery.P2P, p2pKey)
	if err != nil {
		return fmt.Errorf("new peer db: %w", err)
	}

	discoveryNode := discovery.NewNode(&conf.Discovery, peerDB, p2pKey)

	manifests, err := cluster.LoadKnownClustersFromDir(conf.ClusterDir)
	if err != nil {
		return fmt.Errorf("load known cluster: %w", err)
	}
	log.Info().Msgf("Loaded %d DVs", len(manifests.Clusters()))

	connGater := p2p.NewConnGaterForClusters(manifests, nil)
	log.Info().Msgf("Connecting to %d unique peers", len(connGater.PeerIDs))

	p2pNode, err := p2p.NewNode(conf.Discovery.P2P, p2pKey, connGater)
	if err != nil {
		return fmt.Errorf("new p2p node: %w", err)
	}

	monitoring, err := server.New(peerDB, p2pNode, conf.MonitoringAddress)
	if err != nil {
		return fmt.Errorf("new monitoring server: %w", err)
	}

	// Start processes and wait for first error or shutdown.

	var procErr error
	select {
	case err := <-start(monitoring.ListenAndServe):
		procErr = fmt.Errorf("monitoring server: %w", err)
	case err := <-start(discoveryNode.Listen):
		procErr = fmt.Errorf("discv5 server: %w", err)
	case <-shutdownCtx.Done():
		log.Info().Msgf("Shutdown signal detected")
	}
	if procErr != nil {
		// Even though procErr is returned below, also log it in case shutdown errors.
		log.Error().Err(err).Msg("Process error")
	}

	log.Info().Msgf("Shutting down gracefully")

	// Shutdown processes (allow 10s)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	discoveryNode.Close()

	if err := monitoring.Shutdown(ctx); err != nil {
		return fmt.Errorf("stop monitoring server: %w", err)
	}

	return procErr
}

// start calls the function asynchronously and returns a channel that propagates
// a non-nil error response. Nil responses are dropped.
// Note this supports both blocking and non-blocking functions.
func start(fn func() error) <-chan error {
	ch := make(chan error, 1)
	go func() {
		err := fn()
		if err != nil {
			ch <- err
		}
	}()

	return ch
}
