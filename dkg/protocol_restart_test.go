// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg_test

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/dkg"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/relay"
)

// TestRunReplaceOperatorProtocol_ChainedPeerRestartFailsFast covers a production incident:
// a cluster ran two replace-operator ceremonies in a chain, and during the second ceremony
// one peer restarted its charon process mid-DKG. A restarted process cannot rejoin the
// ceremony because the alive peers hold per-ceremony in-memory state (sync protocol steps,
// reliable-broadcast dedup hashes) that the fresh process does not have.
//
// The required behavior is to fail fast on all nodes with actionable errors instead of
// hanging forever:
//   - the alive peers detect the restarted peer (sync step regression) and abort with an
//     error instructing all operators to restart the ceremony together, and
//   - the restarted peer receives the same rejection from its peers and aborts as well.
func TestRunReplaceOperatorProtocol_ChainedPeerRestartFailsFast(t *testing.T) {
	const (
		numValidators    = 1
		numNodes         = 7
		threshold        = 5
		firstReplaceIdx  = 2
		secondReplaceIdx = 4
	)

	relayAddr := relay.StartRelay(t.Context(), t)

	srcClusterDir := createTestCluster(t, numNodes, threshold, numValidators)
	dst1ClusterDir := t.TempDir()
	dst2ClusterDir := t.TempDir()

	srcLockPath := path.Join(nodeDir(srcClusterDir, 0), clusterLockFile)
	srcLock, err := dkg.LoadAndVerifyClusterLock(t.Context(), srcLockPath, "", false)
	require.NoError(t, err)

	// Ceremony 1: replace the operator at firstReplaceIdx with a new operator.
	// This is the control run proving that a chained setup starts from a healthy state.
	newOp1Dir := nodeDir(srcClusterDir, numNodes)
	newOp1ENR := createENR(t, newOp1Dir)

	err = app.CopyFile(srcLockPath, path.Join(newOp1Dir, clusterLockFile))
	require.NoError(t, err)

	ctx1, cancel1 := context.WithCancel(t.Context())
	defer cancel1()

	eg := new(errgroup.Group)
	for n := range numNodes {
		eg.Go(func() error {
			ndir := nodeDir(srcClusterDir, n)
			if n == firstReplaceIdx {
				ndir = newOp1Dir
			}

			replaceConfig := dkg.ReplaceOperatorConfig{
				LockFilePath:     path.Join(ndir, clusterLockFile),
				PrivateKeyPath:   p2p.KeyPath(ndir),
				ValidatorKeysDir: path.Join(ndir, validatorKeysDir),
				OutputDir:        nodeDir(dst1ClusterDir, n),
				NewENR:           newOp1ENR,
				OldENR:           srcLock.Operators[firstReplaceIdx].ENR,
			}

			err := dkg.RunReplaceOperatorProtocol(ctx1, replaceConfig, createDKGConfig(t, relayAddr))
			if err != nil {
				return failNode(t, cancel1, n, err)
			}

			return nil
		})
	}

	require.NoError(t, eg.Wait())
	verifyClusterValidators(t, numValidators, getNodeDirs(dst1ClusterDir, numNodes))
	t.Log("Ceremony 1 (control) completed")

	// Ceremony 2: chained on ceremony 1's output, replace the operator at secondReplaceIdx.
	// A random continuing peer is killed mid-DKG and restarted.
	lock2Path := path.Join(nodeDir(dst1ClusterDir, 0), clusterLockFile)
	lock2, err := dkg.LoadAndVerifyClusterLock(t.Context(), lock2Path, "", false)
	require.NoError(t, err)

	newOp2Dir := nodeDir(srcClusterDir, numNodes+1)
	newOp2ENR := createENR(t, newOp2Dir)

	err = app.CopyFile(lock2Path, path.Join(newOp2Dir, clusterLockFile))
	require.NoError(t, err)

	restartIdx := randomNodeExcept(numNodes, secondReplaceIdx)
	t.Logf("Ceremony 2: replacing operator %d, restarting peer %d mid-DKG", secondReplaceIdx, restartIdx)

	// The restart target logs through a context-scoped watcher (never the global logger,
	// which would race with logging goroutines of other tests). It is killed only once it
	// logs "Starting pedersen reshare": reliable broadcast returns only after ALL peers
	// signed its node pubkey message, so the ceremony state on all alive peers provably
	// references the first process by then.
	watcher := newLogWatcher(t)
	reshareStarted := watcher.watchFor("Starting pedersen reshare")

	ctx2, cancel2 := context.WithCancel(t.Context())
	defer cancel2()

	runNode := func(ctx context.Context, n int, tag string, watcher *logWatcher) error {
		ctx = log.WithCtx(ctx, z.Str("test_node_tag", tag))
		if watcher != nil {
			ctx = log.WithLogger(ctx, watcher.logger)
		}

		ndir := nodeDir(dst1ClusterDir, n)
		if n == secondReplaceIdx {
			ndir = newOp2Dir
		}

		replaceConfig := dkg.ReplaceOperatorConfig{
			LockFilePath:     path.Join(ndir, clusterLockFile),
			PrivateKeyPath:   p2p.KeyPath(ndir),
			ValidatorKeysDir: path.Join(ndir, validatorKeysDir),
			OutputDir:        nodeDir(dst2ClusterDir, n),
			NewENR:           newOp2ENR,
			OldENR:           lock2.Operators[secondReplaceIdx].ENR,
		}

		return dkg.RunReplaceOperatorProtocol(ctx, replaceConfig, createDKGConfig(t, relayAddr))
	}

	type nodeResult struct {
		node int
		err  error
	}

	aliveResults := make(chan nodeResult, numNodes)

	for n := range numNodes {
		if n == restartIdx {
			continue
		}

		go func() {
			aliveResults <- nodeResult{node: n, err: runNode(ctx2, n, fmt.Sprintf("alive-node-%d", n), nil)}
		}()
	}

	// First instance of the restart target.
	restartCtx, restartCancel := context.WithCancel(ctx2)
	defer restartCancel()

	firstRunResult := make(chan error, 1)

	go func() {
		firstRunResult <- runNode(restartCtx, restartIdx, "restart-target-first-run", watcher)
	}()

	select {
	case <-reshareStarted:
	case err := <-firstRunResult:
		t.Fatalf("Restart target exited before starting reshare: %v", err)
	case <-time.After(2 * time.Minute):
		t.Fatal("Timed out waiting for restart target to start pedersen reshare")
	}

	restartCancel()

	select {
	case err := <-firstRunResult:
		t.Logf("Restart target first run returned after kill: %v", err)
	case <-time.After(time.Minute):
		t.Fatal("Restart target first run did not return after context cancel")
	}

	// Second instance: same node directory, fresh process state. The alive peers must
	// reject it promptly with an actionable error instead of letting it churn forever.
	secondRunResult := make(chan error, 1)

	go func() {
		secondRunResult <- runNode(ctx2, restartIdx, "restart-target-second-run", nil)
	}()

	select {
	case err := <-secondRunResult:
		require.Error(t, err, "restarted peer must not rejoin the ceremony successfully")
		require.ErrorContains(t, err, "restart the ceremony together")
		t.Logf("Restarted peer aborted with: %v", err)
	case <-time.After(2 * time.Minute):
		t.Fatal("Restarted peer did not fail fast, expected prompt rejection by alive peers")
	}

	// The alive peers must all abort promptly with diagnosable errors. Depending on where
	// the abort lands on each node, this is the restart detection (best case), a pedersen
	// collection timeout, or a kyber DKG abort due to the dead peer's missing deals.
	deadline := time.After(3 * time.Minute)

	var restartDetected bool

	for range numNodes - 1 {
		select {
		case res := <-aliveResults:
			require.Error(t, res.err, "alive node %d must abort with an error", res.node)

			isRestartErr := strings.Contains(res.err.Error(), "restart the ceremony together")
			isTimeoutErr := strings.Contains(res.err.Error(), "timed out waiting")
			isDKGAbort := strings.Contains(res.err.Error(), "pedersen reshare protocol failed")
			require.True(t, isRestartErr || isTimeoutErr || isDKGAbort,
				"alive node %d error must be actionable, got: %v", res.node, res.err)

			if isRestartErr {
				restartDetected = true
			}

			t.Logf("Alive node %d aborted with: %v", res.node, res.err)
		case <-deadline:
			t.Fatal("Alive peers did not fail fast, expected prompt abort after peer restart")
		}
	}

	require.True(t, restartDetected, "at least one alive peer must detect the peer restart")

	// No artifacts must have been written by the failed ceremony.
	for n := range numNodes {
		require.NoFileExists(t, path.Join(nodeDir(dst2ClusterDir, n), clusterLockFile))
	}
}

// TestRunReplaceOperatorProtocol_PeerDeathCollectTimeout proves that when a peer dies
// mid-DKG and never comes back, the remaining peers do not hang forever waiting for its
// contributions: the pedersen collection points time out with an error naming the missing peer.
func TestRunReplaceOperatorProtocol_PeerDeathCollectTimeout(t *testing.T) {
	const (
		numValidators = 1
		numNodes      = 7
		threshold     = 5
		replaceIdx    = 2
	)

	relayAddr := relay.StartRelay(t.Context(), t)

	srcClusterDir := createTestCluster(t, numNodes, threshold, numValidators)
	dstClusterDir := t.TempDir()

	srcLockPath := path.Join(nodeDir(srcClusterDir, 0), clusterLockFile)
	srcLock, err := dkg.LoadAndVerifyClusterLock(t.Context(), srcLockPath, "", false)
	require.NoError(t, err)

	newOpDir := nodeDir(srcClusterDir, numNodes)
	newOpENR := createENR(t, newOpDir)

	err = app.CopyFile(srcLockPath, path.Join(newOpDir, clusterLockFile))
	require.NoError(t, err)

	killIdx := randomNodeExcept(numNodes, replaceIdx)
	t.Logf("Replacing operator %d, killing peer %d mid-DKG without restart", replaceIdx, killIdx)

	// The kill target logs through a context-scoped watcher, see the fail-fast test above.
	watcher := newLogWatcher(t)
	reshareStarted := watcher.watchFor("Starting pedersen reshare")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Short DKG timeout to keep the collection timeout (and the test) fast.
	dkgConfig := dkg.Config{
		ShutdownDelay: 3 * time.Second,
		Timeout:       30 * time.Second,
		P2P: p2p.Config{
			Relays:   []string{relayAddr},
			TCPAddrs: []string{testutil.AvailableAddr(t).String()},
		},
		Log: log.DefaultConfig(),
	}

	runNode := func(ctx context.Context, n int, tag string, watcher *logWatcher) error {
		ctx = log.WithCtx(ctx, z.Str("test_node_tag", tag))
		if watcher != nil {
			ctx = log.WithLogger(ctx, watcher.logger)
		}

		ndir := nodeDir(srcClusterDir, n)
		if n == replaceIdx {
			ndir = newOpDir
		}

		replaceConfig := dkg.ReplaceOperatorConfig{
			LockFilePath:     path.Join(ndir, clusterLockFile),
			PrivateKeyPath:   p2p.KeyPath(ndir),
			ValidatorKeysDir: path.Join(ndir, validatorKeysDir),
			OutputDir:        nodeDir(dstClusterDir, n),
			NewENR:           newOpENR,
			OldENR:           srcLock.Operators[replaceIdx].ENR,
		}

		return dkg.RunReplaceOperatorProtocol(ctx, replaceConfig, dkgConfig)
	}

	type nodeResult struct {
		node int
		err  error
	}

	aliveResults := make(chan nodeResult, numNodes)

	for n := range numNodes {
		if n == killIdx {
			continue
		}

		go func() {
			aliveResults <- nodeResult{node: n, err: runNode(ctx, n, fmt.Sprintf("alive-node-%d", n), nil)}
		}()
	}

	killCtx, killCancel := context.WithCancel(ctx)
	defer killCancel()

	killResult := make(chan error, 1)

	go func() {
		killResult <- runNode(killCtx, killIdx, "kill-target", watcher)
	}()

	select {
	case <-reshareStarted:
	case err := <-killResult:
		t.Fatalf("Kill target exited before starting reshare: %v", err)
	case <-time.After(2 * time.Minute):
		t.Fatal("Timed out waiting for kill target to start pedersen reshare")
	}

	killCancel()

	select {
	case err := <-killResult:
		t.Logf("Kill target returned after kill: %v", err)
	case <-time.After(time.Minute):
		t.Fatal("Kill target did not return after context cancel")
	}

	// All alive peers must abort with a collection timeout error instead of hanging.
	deadline := time.After(3 * time.Minute)

	for range numNodes - 1 {
		select {
		case res := <-aliveResults:
			require.Error(t, res.err, "alive node %d must abort with an error", res.node)
			require.ErrorContains(t, res.err, "timed out waiting",
				"alive node %d must report a collection timeout", res.node)
			t.Logf("Alive node %d aborted with: %v", res.node, res.err)
		case <-deadline:
			t.Fatal("Alive peers did not abort, expected collection timeout after peer death")
		}
	}
}

// randomNodeExcept returns a random node index in [0, numNodes) excluding the given index.
func randomNodeExcept(numNodes, except int) int {
	var candidates []int

	for n := range numNodes {
		if n != except {
			candidates = append(candidates, n)
		}
	}

	return candidates[rand.IntN(len(candidates))]
}

// logWatcher matches log lines against registered substring watches, closing the watch
// channel on the first matching line. Its logger is attached to a node's context via
// log.WithLogger, which avoids mutating the process-global logger: replacing the global
// logger races with logging goroutines still winding down from other tests.
type logWatcher struct {
	logger *zap.Logger

	mu      sync.Mutex
	watches []*logWatch
}

type logWatch struct {
	substrings []string
	matched    chan struct{}
	done       bool
}

func newLogWatcher(t *testing.T) *logWatcher {
	t.Helper()

	watcher := new(logWatcher)
	watcher.logger = log.NewConsoleForT(t, watcher)

	return watcher
}

// watchFor returns a channel that is closed when a single log line contains all the substrings.
func (w *logWatcher) watchFor(substrings ...string) <-chan struct{} {
	w.mu.Lock()
	defer w.mu.Unlock()

	watch := &logWatch{
		substrings: substrings,
		matched:    make(chan struct{}),
	}
	w.watches = append(w.watches, watch)

	return watch.matched
}

func (w *logWatcher) Write(p []byte) (int, error) {
	line := string(p)

	w.mu.Lock()
	for _, watch := range w.watches {
		if watch.done {
			continue
		}

		match := true

		for _, s := range watch.substrings {
			if !strings.Contains(line, s) {
				match = false
				break
			}
		}

		if match {
			watch.done = true
			close(watch.matched)
		}
	}
	w.mu.Unlock()

	n, err := os.Stderr.Write(p)
	if err != nil {
		return n, errors.Wrap(err, "write stderr")
	}

	return n, nil
}

func (*logWatcher) Sync() error {
	return nil
}
