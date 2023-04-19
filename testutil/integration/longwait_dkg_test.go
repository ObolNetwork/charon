// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package integration_test

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg"
	"github.com/obolnetwork/charon/p2p"
)

func TestLongWaitDKG(t *testing.T) {
	skipIfDisabled(t)

	const (
		threshold = 3
		numNodes  = 4
		numVals   = 10
		relayURL  = "https://0.relay.obol.tech"
		// The time period after which a new node is started.
		window = 10
		// The time period when a node is offline. A window is divided into multiple slots each of nodeDownPeriod duration.
		// A node goes down in one of these slots in a particular window.
		nodeDownPeriod = 2
	)

	var (
		eg              errgroup.Group
		ctx             = log.WithTopic(context.Background(), "longwait")
		dir             = t.TempDir()
		def             = testDef(t, dir, threshold, numNodes, numVals)
		allNodesStarted = make(chan struct{}, numNodes)
	)

	for i := 0; i < numNodes; i++ {
		indx := i
		delay := indx * window
		log.Debug(ctx, "Starting node", z.Int("node", indx), z.Int("delay", delay))

		eg.Go(func() error {
			time.Sleep(time.Duration(delay))

			if indx == numNodes-1 {
				// Notify all nodes that everyone has started. Let the DKG begin!
				for j := 0; j < numNodes; j++ {
					allNodesStarted <- struct{}{}
				}
			}

			return mimicDKGNode(ctx, t, def, dir, relayURL, window, nodeDownPeriod, indx, allNodesStarted)
		})
	}

	err := eg.Wait()
	require.NoError(t, err)
}

// mimicDKGNode mimics the behaviour of a DKG node that randomly stops for sometime before restarting again but finally participates in the DKG.
func mimicDKGNode(ctx context.Context, t *testing.T, def cluster.Definition, dir, relayURL string, window, nodeDownPeriod, nodeIdx int, allNodesStarted chan struct{}) error {
	t.Helper()

	nodeDir := path.Join(dir, fmt.Sprintf("node%d", nodeIdx))
	dkgConf := dkg.Config{
		DataDir: nodeDir,
		P2P: p2p.Config{
			Relays: []string{relayURL},
		},
		Log: log.Config{
			Level: "info",
		},
		ShutdownDelay: 1 * time.Second,
		TestDef:       &def,
	}

	for {
		ctx2, cancel := context.WithCancel(ctx)
		go func(ctx context.Context) {
			log.Debug(ctx, "Starting DKG node", z.Int("node", nodeIdx))

			_ = dkg.Run(ctx, dkgConf)
		}(ctx2)

		var allStarted bool
		select {
		case <-allNodesStarted:
			allStarted = true
		default:
			break
		}

		var modVal int
		if allStarted {
			// If the last node has started, we need to have all nodes active at the last slot of window
			modVal = window - (2*nodeDownPeriod - 1)
		} else {
			modVal = window - (nodeDownPeriod - 1)
		}

		// Let's say we kill the dkg in x time, then we wait for (window-x) time to elapse before starting another dkg instance.
		delayToKill := rand.Int() % modVal
		if delayToKill == 0 {
			delayToKill = 1 // Don't kill the node instantly, rather wait 1s
		}

		// Wait some random duration before killing the node
		log.Debug(ctx, "Killing node after delay", z.Int("node", nodeIdx), z.Int("delay", delayToKill))
		<-time.After(time.Duration(delayToKill) * time.Second)
		cancel()

		// Wait till remaining time before restarting the node
		remainingDelay := window - delayToKill
		log.Debug(ctx, "Waiting before restarting node", z.Int("node", nodeIdx), z.Int("delay", remainingDelay))
		<-time.After(time.Duration(remainingDelay) * time.Second)

		if allStarted {
			break
		}
	}

	// Run final DKG
	log.Debug(ctx, "Running final DKG", z.Int("node", nodeIdx))

	return dkg.Run(ctx, dkgConf)
}

// testDef returns a cluster.Definition for use in tests. It also creates node directories and saves respective charon enr private keys in the corresponding folders.
func testDef(t *testing.T, dir string, threshold, numNodes, numVals int) cluster.Definition {
	t.Helper()

	const frostAlgo = "frost"

	withAlgo := func(algo string) func(*cluster.Definition) {
		return func(d *cluster.Definition) {
			d.DKGAlgorithm = algo
		}
	}

	lock, p2pKeys, _ := cluster.NewForT(t, numVals, threshold, numNodes, 1, withAlgo(frostAlgo))

	for i := 0; i < numNodes; i++ {
		nodeDir := path.Join(dir, fmt.Sprintf("node%d", i))
		require.NoError(t, os.Mkdir(nodeDir, 0o750))

		err := k1util.Save(p2pKeys[i], p2p.KeyPath(nodeDir))
		require.NoError(t, err)
	}

	return lock.Definition
}
