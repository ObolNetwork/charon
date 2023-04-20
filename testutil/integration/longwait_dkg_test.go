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

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

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
		window = 10 * time.Second
		// The time period when a node is offline. A window is divided into multiple slots each of nodeDownPeriod duration.
		// A node goes down in one of these slots in a particular window.
		nodeDownPeriod = 2 * time.Second
	)

	var (
		eg              errgroup.Group
		ctx             = log.WithTopic(context.Background(), "longwait")
		allNodesStarted = make(chan struct{}, numNodes)
	)

	def, p2pKeys := testDef(t, threshold, numNodes, numVals)
	dir := t.TempDir()

	for i, p2pKey := range p2pKeys {
		indx := i
		p2pKey := p2pKey
		if indx > 0 {
			time.Sleep(window)
		}

		eg.Go(func() error {
			nodeDir := path.Join(dir, fmt.Sprintf("node%d", indx))
			require.NoError(t, os.Mkdir(nodeDir, 0o750))

			dkgConf := dkg.Config{
				DataDir: nodeDir,
				P2P: p2p.Config{
					Relays: []string{relayURL},
				},
				Log:           log.DefaultConfig(),
				ShutdownDelay: 1 * time.Second,
				TestConfig: dkg.TestConfig{
					Def:    &def,
					P2PKey: p2pKey,
				},
			}

			log.Debug(ctx, "Starting node (1st time)", z.Int("node", indx))

			return mimicDKGNode(ctx, t, dkgConf, window, nodeDownPeriod, indx, allNodesStarted)
		})
	}

	// Notify all nodes that everyone has started. Let the DKG begin!
	for i := 0; i < numNodes; i++ {
		allNodesStarted <- struct{}{}
	}

	require.NoError(t, eg.Wait())
}

// mimicDKGNode mimics the behaviour of a DKG node that randomly stops for sometime before restarting again but finally participates in the DKG.
func mimicDKGNode(ctx context.Context, t *testing.T, dkgConf dkg.Config, window, nodeDownPeriod time.Duration, nodeIdx int, allNodesStarted chan struct{}) error {
	t.Helper()

	for {
		ctx, cancel := context.WithCancel(ctx)
		go func(ctx context.Context) {
			_ = dkg.Run(ctx, dkgConf)
		}(ctx)

		log.Debug(ctx, "Started DKG node", z.Int("node", nodeIdx))

		var allStarted bool
		select {
		case <-allNodesStarted:
			allStarted = true
		default:
			break
		}

		delayToKill, remainingDelay := calcKillDelay(window, nodeDownPeriod, allStarted)

		// Wait some random duration before killing the node
		log.Debug(ctx, "Killing node after delay", z.Int("node", nodeIdx), z.Int("delay", delayToKill))
		<-time.After(time.Duration(delayToKill) * time.Second)
		cancel()

		// Wait till remaining time before restarting the node
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

// testDef returns a cluster.Definition and k1 p2p keys for use in tests.
func testDef(t *testing.T, threshold, numNodes, numVals int) (cluster.Definition, []*k1.PrivateKey) {
	t.Helper()

	lock, p2pKeys, _ := cluster.NewForT(t, numVals, threshold, numNodes, 1)

	return lock.Definition, p2pKeys
}

// calcKillDelay returns a random delay that the calling process must wait before killing a DKG node. It also returns a remaining delay
// which the calling process must wait after killing a node and before restarting it again.
func calcKillDelay(window, nodeDownPeriod time.Duration, allStarted bool) (int, int) {
	var modVal int

	windowVal := int(window / time.Second)
	nodeDownPeriodVal := int(nodeDownPeriod / time.Second)
	if allStarted {
		// If the last node has started, we need to have all nodes active at the last slot of window
		modVal = windowVal - (2*nodeDownPeriodVal - 1)
	} else {
		modVal = windowVal - (nodeDownPeriodVal - 1)
	}

	// Let's say we kill the dkg in x time, then we wait for (window-x) time to elapse before starting another dkg instance.
	delayToKill := rand.Int() % modVal
	if delayToKill == 0 {
		delayToKill = 1 // Don't kill the node instantly, rather wait 1s
	}

	remainingDelay := windowVal - delayToKill

	return delayToKill, remainingDelay
}
