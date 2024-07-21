// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package integration_test

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path"
	"testing"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg"
	"github.com/obolnetwork/charon/p2p"
)

const ctxCanceledErr = "context canceled"

var (
	nightly  = flag.Bool("nightly", false, "Enable nightly integration tests")
	quickRun = flag.Bool("quick-run", false, "Enable quick long-wait DKG that finishes in a minute")
)

// ^ : indicates node is online.
// - : indicates node is offline.
// Node 0 starts at t=0min and never goes offline.
// Subsequent nodes start after an interval of 10min.
// So, Node 1 starts at t=10min, Node 2 starts at t=20min and so on.
// Each node except Node 0 stops for 2min in every 10min window before restarting again.
// After the last node is started, no node goes offline and the DKG completes.
// +========+============+============+============+============+
// |  Node  |   0-10m    |   10-20m   |   20-30m   |   30-40m   |
// +========+============+============+============+============+
// | Node 0 | ^^^^^^^^^^ | ^^^^^^^^^^ | ^^^^^^^^^^ | ^^^^^^^^^^ |
// +--------+------------+------------+------------+------------+
// | Node 1 | ---------- | ^^^--^^^^^ | ^^^^^^--^^ | ^^^^^^^^^^ |
// +--------+------------+------------+------------+------------+
// | Node 2 | ---------- | ---------- | ^--^^^^^^^ | ^^^^^^^^^^ |
// +--------+------------+------------+------------+------------+
// | Node 3 | ---------- | ---------- | ---------- | ^^^^^^^^^^ |
// +--------+------------+------------+------------+------------+

func TestLongWaitDKG(t *testing.T) {
	if !*nightly {
		t.Skip("Nightly tests are disabled")
	}

	const (
		threshold = 3
		numNodes  = 4
		numVals   = 10
		relayURL  = "https://0.relay.obol.tech"
	)

	var (
		// The time period after which a new node is started.
		window = 10 * time.Minute
		// The time period when a node is offline. A node randomly goes down for this duration in a given window.
		nodeDownPeriod = 2 * time.Minute
	)

	if *quickRun {
		window = 10 * time.Second
		nodeDownPeriod = 2 * time.Second
	}

	var (
		eg              errgroup.Group
		ctx             = log.WithTopic(context.Background(), "longwait")
		allNodesStarted = make(chan struct{}, numNodes)
	)

	def, p2pKeys := testDef(t, threshold, numNodes, numVals)
	dir := t.TempDir()
	dkgConf := dkg.Config{
		P2P: p2p.Config{
			Relays: []string{relayURL},
		},
		Log:           log.DefaultConfig(),
		ShutdownDelay: 1 * time.Second,
		TestConfig: dkg.TestConfig{
			Def: &def,
		},
		Timeout: 10 * time.Minute,
	}

	windowTicker := time.NewTicker(window)
	onStartup := make(chan struct{}, 1)
	onStartup <- struct{}{}
	newWindowStarted := make(chan struct{}, numNodes)
	var currIdx int
	for {
		p2pKey := p2pKeys[currIdx]
		nodeDir := path.Join(dir, fmt.Sprintf("node%d", currIdx))
		require.NoError(t, os.Mkdir(nodeDir, 0o750))
		conf := dkgConf
		conf.DataDir = nodeDir
		conf.TestConfig.P2PKey = p2pKey

		runDKG := func() {
			i := currIdx
			eg.Go(func() error {
				return mimicDKGNode(ctx, t, conf, window, nodeDownPeriod, i, allNodesStarted, newWindowStarted)
			})
		}

		select {
		case <-onStartup:
			runDKG() // Start node 0
		case <-windowTicker.C:
			runDKG() // Start a node every window
		}

		if currIdx == numNodes-1 {
			// Notify all nodes that everyone has started.
			for range numNodes {
				allNodesStarted <- struct{}{}
			}

			break
		}

		// Notify already running nodes that a new window has started.
		// Note that currIdx+1 nodes are running by now.
		for range currIdx + 1 {
			newWindowStarted <- struct{}{}
		}

		currIdx++
	}

	require.NoError(t, eg.Wait())
}

// mimicDKGNode mimics the behaviour of a DKG node that randomly stops for sometime before restarting again but finally participates in the DKG.
func mimicDKGNode(parentCtx context.Context, t *testing.T, dkgConf dkg.Config, window, nodeDownPeriod time.Duration, nodeIdx int, allNodesStarted, newWindowStarted chan struct{}) error {
	t.Helper()

	var (
		ctx        context.Context
		cancelFunc context.CancelFunc
		firstNode  bool   // True if node index is 0
		allStarted bool   // True if all nodes have started DKG
		firstTime  = true // True if the node is starting for the first time
	)

	firstNode = nodeIdx == 0

	// runDKG runs a new instance of DKG. If a DKG is already running, it stops it before starting a new one.
	runDKG := func() {
		// If there's an instance already running, stop it
		if ctx != nil {
			cancelFunc()
		}

		ctx, cancelFunc = context.WithCancel(parentCtx)
		log.Debug(ctx, "Starting DKG node", z.Int("node", nodeIdx), z.Bool("first_time", firstTime))

		errCh := make(chan error, 1)
		go func(ctx context.Context) {
			// Ensure DKGs don't save their artifacts in the same node directory since the current DKG would error
			// as it would find an existing private key lock file previously created by earlier DKGs.
			conf := dkgConf
			conf.DataDir = t.TempDir()
			err := dkg.Run(ctx, conf)
			errCh <- err
		}(ctx)
		err := <-errCh
		require.ErrorContains(t, err, ctxCanceledErr)
	}

	for {
		select {
		case <-allNodesStarted:
			allStarted = true
		case <-newWindowStarted:
			if firstNode && !firstTime { // Node 0 never restarts (is always up)
				log.Debug(ctx, "Not restarting node", z.Int("node", nodeIdx))
				continue
			}

			// Start the node
			runDKG()
			firstTime = false
			if firstNode {
				continue
			}

			// Wait for some random duration before stopping the node
			stopDelay := calcStopDelay(t, window, nodeDownPeriod)
			log.Debug(ctx, "Stopping node after delay", z.Int("node", nodeIdx), z.Str("delay", stopDelay.String()))
			select {
			case <-time.After(stopDelay):
			case <-allNodesStarted:
				allStarted = true
			}

			// Stop the node
			cancelFunc()
			log.Debug(ctx, "Node stopped", z.Int("node", nodeIdx))

			// If all nodes have started, there's no point in restarting the node
			if allStarted {
				break
			}

			// Wait nodeDownPeriod before restarting the node
			log.Debug(ctx, "Waiting before restarting node", z.Int("node", nodeIdx), z.Str("delay", nodeDownPeriod.String()))
			select {
			case <-time.After(nodeDownPeriod):
				runDKG()
			case <-allNodesStarted:
				allStarted = true
			}
		}

		if allStarted {
			break
		}
	}

	// Stop any existing running DKG and run the final DKG since all nodes are up now
	if ctx != nil {
		cancelFunc()
	}

	log.Debug(parentCtx, "Running final DKG", z.Int("node", nodeIdx))

	return dkg.Run(parentCtx, dkgConf)
}

// testDef returns a cluster.Definition and k1 p2p keys for use in tests.
func testDef(t *testing.T, threshold, numNodes, numVals int) (cluster.Definition, []*k1.PrivateKey) {
	t.Helper()

	seed := 1
	random := rand.New(rand.NewSource(int64(seed)))
	lock, p2pKeys, _ := cluster.NewForT(t, numVals, threshold, numNodes, seed, random)

	return lock.Definition, p2pKeys
}

// calcStopDelay returns a random delay that the calling process must wait before stopping a DKG node.
func calcStopDelay(t *testing.T, window, nodeDownPeriod time.Duration) time.Duration {
	t.Helper()

	windowVal := int(window / time.Second)
	nodeDownPeriodVal := int(nodeDownPeriod / time.Second)
	modVal := windowVal - (nodeDownPeriodVal - 1)

	stopDelay := rand.Int() % modVal
	if stopDelay == 0 {
		stopDelay = 1 // Don't stop the node instantly, rather wait 1min
	}

	return time.Duration(stopDelay) * time.Second
}

func TestDKGWithHighValidatorsAmt(t *testing.T) {
	if !*nightly {
		t.Skip("Nightly tests are disabled")
	}

	const (
		threshold = 3
		numNodes  = 4
		numVals   = 200
		relayURL  = "https://0.relay.obol.tech"
	)

	var (
		eg  errgroup.Group
		ctx = log.WithTopic(context.Background(), "5kvalidators")
	)

	def, p2pKeys := testDef(t, threshold, numNodes, numVals)

	dkgConf := dkg.Config{
		P2P: p2p.Config{
			Relays: []string{relayURL},
		},
		Log:           log.DefaultConfig(),
		ShutdownDelay: 1 * time.Second,
		TestConfig: dkg.TestConfig{
			Def: &def,
		},
		Timeout: 10 * time.Minute,
	}

	dir := t.TempDir()

	for idx := range numNodes {
		eg.Go(func() error {
			conf := dkgConf
			conf.DataDir = path.Join(dir, fmt.Sprintf("node%d", idx))

			require.NoError(t, os.MkdirAll(conf.DataDir, 0o755))
			err := k1util.Save(p2pKeys[idx], p2p.KeyPath(conf.DataDir))
			require.NoError(t, err)

			if err := dkg.Run(ctx, conf); err != nil {
				return errors.Wrap(err, "dkg failed", z.Int("node_idx", idx))
			}

			return nil
		})
	}

	require.NoError(t, eg.Wait())
}
