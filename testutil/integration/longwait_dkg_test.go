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
	// skipIfDisabled(t)

	const (
		threshold     = 3
		numNodes      = 4
		numVals       = 10
		sleepDuration = 10 * time.Second
		relayURL      = "https://0.relay.obol.tech"
	)

	dir := t.TempDir()
	startedChan := make(chan struct{})

	startDKG := func(ctx context.Context, def cluster.Definition, nodeIdx int) error {
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

		log.Info(ctx, "Starting DKG node", z.Int("index", nodeIdx))
		startedChan <- struct{}{}
		err := dkg.Run(ctx, dkgConf)

		return err
	}

	def := testDef(t, dir, threshold, numNodes, numVals)

	var eg errgroup.Group
	var cancelFuncs []context.CancelFunc
	for i := 0; i < numNodes; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancelFuncs = append(cancelFuncs, cancel)
		indx := i
		delay := time.Duration(indx) * sleepDuration
		t.Logf("Starting node %d in %f seconds", indx, delay.Seconds())
		eg.Go(func() error {
			time.Sleep(delay)

			return startDKG(ctx, def, indx)
		})
	}

	go func() {
		err := eg.Wait()
		require.ErrorContains(t, err, "context canceled")
	}()

	randomOrder := genRandomPerm(numNodes) // Ex: [2, 0, 1, 3]

	waitAll(t, startedChan, numNodes)

	t.Log("Start killing DKG nodes randomly", randomOrder)

	var eg2 errgroup.Group // To wait for the restarted goroutines
	for _, indx := range randomOrder {
		cancelFuncs[indx]()
		t.Log("Just killed node", indx)

		// Start the node again after 5 seconds
		time.Sleep(5 * time.Second)

		i := indx
		eg2.Go(func() error {
			return startDKG(context.Background(), def, i)
		})
	}

	waitAll(t, startedChan, numNodes)

	require.NoError(t, eg2.Wait())
}

// testDef returns a test cluster.Definition.
func testDef(t *testing.T, dir string, threshold, numNodes, numVals int) cluster.Definition {
	t.Helper()

	const frost = "frost"

	withAlgo := func(algo string) func(*cluster.Definition) {
		return func(d *cluster.Definition) {
			d.DKGAlgorithm = algo
		}
	}

	lock, p2pKeys, _ := cluster.NewForT(t, numVals, threshold, numNodes, 1, withAlgo(frost))

	for i := 0; i < numNodes; i++ {
		nodeDir := path.Join(dir, fmt.Sprintf("node%d", i))
		require.NoError(t, os.Mkdir(nodeDir, 0o750))

		err := k1util.Save(p2pKeys[i], p2p.KeyPath(nodeDir))
		require.NoError(t, err)
	}

	return lock.Definition
}

func genRandomPerm(numNodes int) []int {
	var a []int
	for i := 0; i < numNodes; i++ {
		a = append(a, i)
	}

	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	random.Shuffle(len(a), func(i, j int) { a[i], a[j] = a[j], a[i] })

	return a
}

// waitAll blocks until numNodes values are received in the provided channel.
func waitAll(t *testing.T, startedChan chan struct{}, numNodes int) {
	t.Helper()

	startedNodeCount := 0
	for {
		<-startedChan
		startedNodeCount++
		if startedNodeCount == numNodes {
			t.Log("All DKG nodes have restarted")
			break
		}
	}
}
