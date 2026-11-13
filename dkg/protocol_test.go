// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
	"github.com/obolnetwork/charon/cmd"
	"github.com/obolnetwork/charon/dkg"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/relay"
)

const (
	clusterLockFile  = "cluster-lock.json"
	validatorKeysDir = "validator_keys"
)

func TestRemoveOperatorsProtocol_BelowF(t *testing.T) {
	const (
		numValidators = 3
		numNodes      = 7
		threshold     = 5
	)

	srcClusterDir := createTestCluster(t, numNodes, threshold, numValidators)
	dstClusterDir := t.TempDir()

	lockFilePath := path.Join(nodeDir(srcClusterDir, 0), clusterLockFile)
	lock, err := dkg.LoadAndVerifyClusterLock(t.Context(), lockFilePath, "", false)
	require.NoError(t, err)

	// We are removing 2 operators, which is <= f (which is 2 for 7 nodes).
	oldENRs := []string{
		lock.Operators[0].ENR,
		lock.Operators[3].ENR,
	}
	oldIndices := []int{0, 3}
	outputNodeDirs := getNodeDirs(dstClusterDir, numNodes, 0, 3)
	wantConfig := loadProposerConfig(t, nodeDir(srcClusterDir, 1))

	// Operator 2 has no file and carries the config derived from the lock, which equals the created cluster's.
	require.NoError(t, os.Remove(proposerconfig.FilePath(nodeDir(srcClusterDir, 2))))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	runProtocol(t, numNodes, func(relayAddr string, n int) error {
		if slices.Contains(oldIndices, n) {
			// Removed nodes do not run the protocol.
			return nil
		}

		dkgConfig := createDKGConfig(t, relayAddr)
		ndir := nodeDir(srcClusterDir, n)
		removeConfig := dkg.RemoveOperatorsConfig{
			LockFilePath:       path.Join(ndir, clusterLockFile),
			PrivateKeyPath:     p2p.KeyPath(ndir),
			ValidatorKeysDir:   path.Join(ndir, validatorKeysDir),
			OutputDir:          nodeDir(dstClusterDir, n),
			RemovingENRs:       oldENRs,
			ProposerConfigFile: proposerconfig.FilePath(ndir),
			OverridesFile:      overridesPath(ndir),
		}

		err := dkg.RunRemoveOperatorsProtocol(ctx, removeConfig, dkgConfig)
		if err != nil {
			return failNode(t, cancel, n, err)
		}

		return nil
	})

	verifyClusterValidators(t, numValidators, outputNodeDirs)
	verifyCarriedProposerConfigs(t, outputNodeDirs, wantConfig)
}

func TestRemoveOperatorsProtocol_MoreThanF(t *testing.T) {
	const (
		numValidators = 3
		numNodes      = 7
		threshold     = 5
	)

	srcClusterDir := createTestCluster(t, numNodes, threshold, numValidators)
	dstClusterDir := t.TempDir()

	lockFilePath := path.Join(nodeDir(srcClusterDir, 0), clusterLockFile)
	lock, err := dkg.LoadAndVerifyClusterLock(t.Context(), lockFilePath, "", false)
	require.NoError(t, err)

	oldENRs := []string{
		lock.Operators[0].ENR,
		lock.Operators[3].ENR,
		lock.Operators[4].ENR,
	}
	outputNodeDirs := getNodeDirs(dstClusterDir, numNodes, 0, 3, 4)
	wantConfig := loadProposerConfig(t, nodeDir(srcClusterDir, 1))

	// The removed but participating operator's unsigned drift does not block the removal.
	writeProposerConfigs(t, *lock, srcClusterDir, []int{0}, 0, divergingProposerConfig(t, *lock, "https://drift.example.com"))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	participating := []int{0, 1, 2, 5, 6} // 0 is old but participating

	runProtocol(t, numNodes, func(relayAddr string, n int) error {
		if !slices.Contains(participating, n) {
			// Non-participating nodes do not run the protocol.
			return nil
		}

		dkgConfig := createDKGConfig(t, relayAddr)
		ndir := nodeDir(srcClusterDir, n)
		removeConfig := dkg.RemoveOperatorsConfig{
			LockFilePath:       path.Join(ndir, clusterLockFile),
			PrivateKeyPath:     p2p.KeyPath(ndir),
			ValidatorKeysDir:   path.Join(ndir, validatorKeysDir),
			OutputDir:          nodeDir(dstClusterDir, n),
			RemovingENRs:       oldENRs,
			ProposerConfigFile: proposerconfig.FilePath(ndir),
			OverridesFile:      overridesPath(ndir),
			ParticipatingENRs: []string{
				lock.Operators[0].ENR, // to be removed, but participating
				lock.Operators[1].ENR, // staying
				lock.Operators[2].ENR, // staying
				lock.Operators[5].ENR, // staying
				lock.Operators[6].ENR, // staying
			},
		}

		err := dkg.RunRemoveOperatorsProtocol(ctx, removeConfig, dkgConfig)
		if err != nil {
			return failNode(t, cancel, n, err)
		}

		return nil
	})

	verifyClusterValidators(t, numValidators, outputNodeDirs)
	verifyCarriedProposerConfigs(t, outputNodeDirs, wantConfig)

	for _, n := range []int{0, 3, 4} {
		require.NoFileExists(t, proposerconfig.FilePath(nodeDir(dstClusterDir, n)))
	}
}

func TestRemoveOperatorsProtocol_AllNodes(t *testing.T) {
	const (
		numValidators = 3
		numNodes      = 4
		threshold     = 3
	)

	srcClusterDir := createTestCluster(t, numNodes, threshold, numValidators)
	dstClusterDir := t.TempDir()

	lockFilePath := path.Join(nodeDir(srcClusterDir, 0), clusterLockFile)
	lock, err := dkg.LoadAndVerifyClusterLock(t.Context(), lockFilePath, "", false)
	require.NoError(t, err)

	// Attempt to remove all nodes from the original cluster
	oldENRs := []string{
		lock.Operators[0].ENR,
		lock.Operators[1].ENR,
		lock.Operators[2].ENR,
		lock.Operators[3].ENR,
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var errorReported atomic.Bool

	runProtocol(t, numNodes, func(relayAddr string, n int) error {
		dkgConfig := createDKGConfig(t, relayAddr)
		ndir := nodeDir(srcClusterDir, n)
		removeConfig := dkg.RemoveOperatorsConfig{
			LockFilePath:     path.Join(ndir, clusterLockFile),
			PrivateKeyPath:   p2p.KeyPath(ndir),
			ValidatorKeysDir: path.Join(ndir, validatorKeysDir),
			OutputDir:        nodeDir(dstClusterDir, n),
			RemovingENRs:     oldENRs,
			ParticipatingENRs: []string{
				lock.Operators[0].ENR,
				lock.Operators[1].ENR,
				lock.Operators[2].ENR,
				lock.Operators[3].ENR,
			},
		}

		err := dkg.RunRemoveOperatorsProtocol(ctx, removeConfig, dkgConfig)
		if err != nil {
			if strings.Contains(err.Error(), "remove operation would remove all nodes from original cluster") {
				errorReported.Store(true)
			}

			return nil
		}

		return err
	})

	require.True(t, errorReported.Load(), "Expected error when attempting to remove all nodes from original cluster")
}

func TestRemoveOperatorsProtocol_DefaultThreshold(t *testing.T) {
	const (
		numValidators = 2
		numNodes      = 4
		threshold     = 3
	)

	srcClusterDir := createTestCluster(t, numNodes, threshold, numValidators)
	dstClusterDir := t.TempDir()

	lockFilePath := path.Join(nodeDir(srcClusterDir, 0), clusterLockFile)
	lock, err := dkg.LoadAndVerifyClusterLock(t.Context(), lockFilePath, "", false)
	require.NoError(t, err)

	// Removing a middle operator so the resulting cluster size (3) exercises
	// both the ceil(2n/3) threshold default and share index compaction.
	oldENRs := []string{lock.Operators[1].ENR}
	outputNodeDirs := getNodeDirs(dstClusterDir, numNodes, 1)
	wantConfig := loadProposerConfig(t, nodeDir(srcClusterDir, 0))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	runProtocol(t, numNodes, func(relayAddr string, n int) error {
		if n == 1 {
			// Removed node does not run the protocol.
			return nil
		}

		dkgConfig := createDKGConfig(t, relayAddr)
		ndir := nodeDir(srcClusterDir, n)
		removeConfig := dkg.RemoveOperatorsConfig{
			LockFilePath:       path.Join(ndir, clusterLockFile),
			PrivateKeyPath:     p2p.KeyPath(ndir),
			ValidatorKeysDir:   path.Join(ndir, validatorKeysDir),
			OutputDir:          nodeDir(dstClusterDir, n),
			RemovingENRs:       oldENRs,
			ProposerConfigFile: proposerconfig.FilePath(ndir),
			OverridesFile:      overridesPath(ndir),
		}

		err := dkg.RunRemoveOperatorsProtocol(ctx, removeConfig, dkgConfig)
		if err != nil {
			return failNode(t, cancel, n, err)
		}

		return nil
	})

	for _, ndir := range outputNodeDirs {
		newLock, err := dkg.LoadAndVerifyClusterLock(t.Context(), path.Join(ndir, clusterLockFile), "", false)
		require.NoError(t, err)
		require.Equal(t, cluster.Threshold(numNodes-1), newLock.Threshold)
		require.Equal(t, 2, newLock.Threshold)
	}

	verifyClusterValidators(t, numValidators, outputNodeDirs)
	verifyCarriedProposerConfigs(t, outputNodeDirs, wantConfig)
}

func TestRunAddOperatorsProtocol(t *testing.T) {
	const (
		numValidators = 3
		numNodes      = 4
		threshold     = 3
		newNodes      = 3
	)

	srcClusterDir := createTestCluster(t, numNodes, threshold, numValidators)
	dstClusterDir := t.TempDir()
	totalNodes := numNodes + newNodes

	lock, err := dkg.LoadAndVerifyClusterLock(t.Context(), path.Join(nodeDir(srcClusterDir, 0), clusterLockFile), "", false)
	require.NoError(t, err)

	wantConfig := divergingProposerConfig(t, *lock, "https://builder.example.com")
	writeProposerConfigs(t, *lock, srcClusterDir, getNodeIdxs(numNodes), 2, wantConfig)

	enrs := make([]string, 0, newNodes)

	for n := numNodes; n < totalNodes; n++ {
		ndir := nodeDir(srcClusterDir, n)
		enr := createENR(t, ndir)
		enrs = append(enrs, enr)

		err := app.CopyFile(path.Join(nodeDir(srcClusterDir, 0), clusterLockFile), path.Join(ndir, clusterLockFile))
		require.NoError(t, err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	runProtocol(t, totalNodes, func(relayAddr string, n int) error {
		dkgConfig := createDKGConfig(t, relayAddr)
		ndir := nodeDir(srcClusterDir, n)
		addConfig := dkg.AddOperatorsConfig{
			LockFilePath:       path.Join(ndir, clusterLockFile),
			PrivateKeyPath:     p2p.KeyPath(ndir),
			ValidatorKeysDir:   path.Join(ndir, validatorKeysDir),
			OutputDir:          nodeDir(dstClusterDir, n),
			NewENRs:            enrs,
			ProposerConfigFile: proposerconfig.FilePath(ndir),
			OverridesFile:      overridesPath(ndir),
		}

		err := dkg.RunAddOperatorsProtocol(ctx, addConfig, dkgConfig)
		if err != nil {
			return failNode(t, cancel, n, err)
		}

		return nil
	})

	verifyClusterValidators(t, numValidators, getNodeDirs(dstClusterDir, totalNodes))
	verifyCarriedProposerConfigs(t, getNodeDirs(dstClusterDir, totalNodes), wantConfig)
}

func TestRunReplaceOperatorProtocol(t *testing.T) {
	const (
		numValidators = 3
		numNodes      = 4
		threshold     = 3
	)

	srcClusterDir := createTestCluster(t, numNodes, threshold, numValidators)
	dstClusterDir := t.TempDir()

	lockFilePath := path.Join(nodeDir(srcClusterDir, 0), clusterLockFile)
	lock, err := dkg.LoadAndVerifyClusterLock(t.Context(), lockFilePath, "", false)
	require.NoError(t, err)

	// replacing operator at index 2
	replacingIndex := 2

	wantConfig := divergingProposerConfig(t, *lock, "https://builder.example.com")
	writeProposerConfigs(t, *lock, srcClusterDir, getNodeIdxs(numNodes), 2, wantConfig)

	// Create a separate directory for the new operator (since it's a different entity)
	newOpNodeDir := nodeDir(srcClusterDir, numNodes) // Create directory for new operator who doesn't have existing cluster data
	newOpEnr := createENR(t, newOpNodeDir)

	// The joining operator adopts the others' config, a stray file in its directory is ignored.
	require.NoError(t, os.MkdirAll(path.Dir(proposerconfig.FilePath(newOpNodeDir)), 0o755))
	require.NoError(t, os.WriteFile(proposerconfig.FilePath(newOpNodeDir), []byte("{"), 0o644))

	err = app.CopyFile(path.Join(nodeDir(srcClusterDir, 0), clusterLockFile), path.Join(newOpNodeDir, clusterLockFile))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// All 4 nodes run the protocol, but we map the new operator to replace the old one
	runProtocol(t, numNodes, func(relayAddr string, n int) error {
		dkgConfig := createDKGConfig(t, relayAddr)

		var ndir string

		if n == replacingIndex {
			// New operator takes over index 2 (uses new operator's directory and keys)
			ndir = newOpNodeDir
		} else {
			// Continuing operators use their original directories
			ndir = nodeDir(srcClusterDir, n)
		}

		replaceConfig := dkg.ReplaceOperatorConfig{
			LockFilePath:       path.Join(ndir, clusterLockFile),
			PrivateKeyPath:     p2p.KeyPath(ndir),
			ValidatorKeysDir:   path.Join(ndir, validatorKeysDir),
			OutputDir:          nodeDir(dstClusterDir, n),
			NewENR:             newOpEnr,
			OldENR:             lock.Operators[replacingIndex].ENR,
			ProposerConfigFile: proposerconfig.FilePath(ndir),
			OverridesFile:      overridesPath(ndir),
		}

		err := dkg.RunReplaceOperatorProtocol(ctx, replaceConfig, dkgConfig)
		if err != nil {
			return failNode(t, cancel, n, err)
		}

		return nil
	})

	verifyClusterValidators(t, numValidators, getNodeDirs(dstClusterDir, numNodes))
	verifyCarriedProposerConfigs(t, getNodeDirs(dstClusterDir, numNodes), wantConfig)
}

func TestRunReshareProtocol(t *testing.T) {
	const (
		numValidators = 3
		numNodes      = 7
		threshold     = 5
	)

	srcClusterDir := createTestCluster(t, numNodes, threshold, numValidators)
	dstClusterDir := t.TempDir()

	lock, err := dkg.LoadAndVerifyClusterLock(t.Context(), path.Join(nodeDir(srcClusterDir, 0), clusterLockFile), "", false)
	require.NoError(t, err)

	wantConfig := divergingProposerConfig(t, *lock, "https://builder.example.com")
	writeProposerConfigs(t, *lock, srcClusterDir, getNodeIdxs(numNodes), 2, wantConfig)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	runProtocol(t, numNodes, func(relayAddr string, n int) error {
		err := dkg.RunReshareProtocol(ctx, reshareTestConfig(t, relayAddr, srcClusterDir, dstClusterDir, n))
		if err != nil {
			return failNode(t, cancel, n, err)
		}

		return nil
	})

	verifyClusterValidators(t, numValidators, getNodeDirs(dstClusterDir, numNodes))
	verifyCarriedProposerConfigs(t, getNodeDirs(dstClusterDir, numNodes), wantConfig)
}

func TestRunReshareProtocol_ProposerConfigMismatch(t *testing.T) {
	const (
		numValidators = 2
		numNodes      = 4
		threshold     = 3
	)

	srcClusterDir := createTestCluster(t, numNodes, threshold, numValidators)
	dstClusterDir := t.TempDir()

	lock, err := dkg.LoadAndVerifyClusterLock(t.Context(), path.Join(nodeDir(srcClusterDir, 0), clusterLockFile), "", false)
	require.NoError(t, err)

	// Operator 1 has an unsigned revision 0 file with another builder list than the signed one of the others.
	writeProposerConfigs(t, *lock, srcClusterDir, []int{1}, 0, divergingProposerConfig(t, *lock, "https://drift.example.com"))

	errs := make([]error, numNodes)

	runProtocolAllowFailures(t, numNodes, func(relayAddr string, n int) error {
		errs[n] = dkg.RunReshareProtocol(t.Context(), reshareTestConfig(t, relayAddr, srcClusterDir, dstClusterDir, n))

		return nil
	})

	for n, err := range errs {
		require.ErrorContains(t, err, "proposer config mismatch between operators", "node %d", n)
		require.ErrorContains(t, err, "peer 1 differs from peer 0", "node %d", n)
		require.ErrorContains(t, err, "default.builder.urls", "node %d", n)
		require.ErrorContains(t, err, "charon alpha edit proposer-config", "node %d", n)
		require.NoDirExists(t, nodeDir(dstClusterDir, n))
	}
}

func reshareTestConfig(t *testing.T, relayAddr, srcClusterDir, dstClusterDir string, n int) dkg.ReshareConfig {
	t.Helper()

	dataDir := nodeDir(srcClusterDir, n)

	return dkg.ReshareConfig{
		DKGConfig:          createDKGConfig(t, relayAddr),
		PrivateKeyPath:     p2p.KeyPath(dataDir),
		LockFilePath:       path.Join(dataDir, clusterLockFile),
		ValidatorKeysDir:   path.Join(dataDir, validatorKeysDir),
		OutputDir:          nodeDir(dstClusterDir, n),
		ProposerConfigFile: proposerconfig.FilePath(dataDir),
		OverridesFile:      overridesPath(dataDir),
	}
}

func TestRunProtocol(t *testing.T) {
	const (
		numValidators = 2
		numNodes      = 4
		threshold     = 3
	)

	clusterDir := createTestCluster(t, numNodes, threshold, numValidators)

	stepsCounterCh := make(chan int, numNodes)

	runProtocol(t, numNodes, func(relayAddr string, n int) error {
		protocol := newTestProtocol()
		ndir := nodeDir(clusterDir, n)

		config := dkg.Config{
			ShutdownDelay: 3 * time.Second,
			Timeout:       time.Minute,
			P2P: p2p.Config{
				Relays:   []string{relayAddr},
				TCPAddrs: []string{testutil.AvailableAddr(t).String()},
			},
		}

		defer func() {
			stepsCounterCh <- protocol.stepCounter
		}()

		lockFilePath := path.Join(ndir, clusterLockFile)
		privateKeyPath := p2p.KeyPath(ndir)
		validatorKeysDir := path.Join(ndir, validatorKeysDir)

		return dkg.RunProtocol(t.Context(), protocol, lockFilePath, privateKeyPath, validatorKeysDir, config)
	})

	for range numNodes {
		steps := <-stepsCounterCh
		require.Equal(t, 2, steps)
	}
}

type testProtocol struct {
	stepCounter int
}

var _ dkg.Protocol = (*testProtocol)(nil)

func newTestProtocol() *testProtocol {
	return &testProtocol{}
}

func (p *testProtocol) GetPeers(lock *cluster.Lock) ([]p2p.Peer, error) {
	return lock.Peers()
}

func (p *testProtocol) PostInit(context.Context, *dkg.ProtocolContext) error {
	return nil
}

func (p *testProtocol) Steps(*dkg.ProtocolContext) []dkg.ProtocolStep {
	return []dkg.ProtocolStep{
		&someStep{p: p},
		&someStep{p: p},
	}
}

type someStep struct {
	p *testProtocol
}

func (s *someStep) Run(ctx context.Context, pctx *dkg.ProtocolContext) error {
	s.p.stepCounter++

	return nil
}

// TestRunProtocol_ShutdownRace tests that the shutdown synchronization works correctly.
// This test verifies the fix for a race condition where one node completing shutdown
// would tear down P2P before other nodes finished their shutdown sync. The fix adds
// a "shutdown ready" sync step before any node begins teardown.
//
// Note: If a node crashes (closes P2P host), the protocol will still fail as expected.
// The fix only prevents failures from transient network issues during normal shutdown.
func TestRunProtocol_ShutdownRace(t *testing.T) {
	const (
		numValidators = 2
		numNodes      = 4
		threshold     = 3
	)

	clusterDir := createTestCluster(t, numNodes, threshold, numValidators)

	var (
		completed atomic.Int32
		failed    atomic.Int32
	)

	// Test with very short shutdown delay - the sync barrier ensures
	// all nodes are ready before teardown begins.
	runProtocolAllowFailures(t, numNodes, func(relayAddr string, n int) error {
		protocol := newTestProtocol()
		ndir := nodeDir(clusterDir, n)

		config := dkg.Config{
			ShutdownDelay: 10 * time.Millisecond, // Very short delay - sync barrier should handle coordination
			Timeout:       time.Minute,
			P2P: p2p.Config{
				Relays:   []string{relayAddr},
				TCPAddrs: []string{testutil.AvailableAddr(t).String()},
			},
		}

		lockFilePath := path.Join(ndir, clusterLockFile)
		privateKeyPath := p2p.KeyPath(ndir)
		validatorKeysDir := path.Join(ndir, validatorKeysDir)

		err := dkg.RunProtocol(t.Context(), protocol, lockFilePath, privateKeyPath, validatorKeysDir, config)
		if err != nil {
			t.Logf("Node %d failed: %v", n, err)
			failed.Add(1)
		} else {
			completed.Add(1)
		}

		return nil
	})

	t.Logf("Completed nodes: %d, Failed nodes: %d", completed.Load(), failed.Load())
	require.Equal(t, int32(numNodes), completed.Load(), "All nodes should complete successfully")
}

// runProtocolAllowFailures is like runProtocol but doesn't fail the test if nodes return errors.
func runProtocolAllowFailures(t *testing.T, numNodes int, nodeFunc func(string, int) error) {
	t.Helper()

	eg := new(errgroup.Group)
	relayAddr := relay.StartRelay(t.Context(), t)

	for n := range numNodes {
		eg.Go(func() error {
			return nodeFunc(relayAddr, n)
		})
	}

	// Ignore errors - the test will check completed/failed counts
	_ = eg.Wait()
}

func createTestCluster(t *testing.T, numNodes, threshold, numValidators int) string {
	t.Helper()

	clusterDir := t.TempDir()

	args := []string{
		"create", "cluster",
		"--cluster-dir", clusterDir,
		"--nodes", strconv.Itoa(numNodes),
		"--threshold", strconv.Itoa(threshold),
		"--num-validators", strconv.Itoa(numValidators),
		"--network", eth2util.Hoodi.Name,
		"--fee-recipient-addresses", "0x0000000000000000000000000000000000000000",
		"--withdrawal-addresses", "0x0000000000000000000000000000000000000000",
	}

	cmd := cmd.New()
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(t.Context())
	require.NoError(t, err)

	return clusterDir
}

func createENR(t *testing.T, dataDir string) string {
	t.Helper()

	args := []string{
		"create", "enr",
		"--data-dir", dataDir,
	}

	var stdout bytes.Buffer

	cmd := cmd.New()
	cmd.SetArgs(args)
	cmd.SetOut(&stdout)
	err := cmd.ExecuteContext(t.Context())
	require.NoError(t, err)

	return strings.Split(stdout.String(), "\n")[1]
}

func runProtocol(t *testing.T, numNodes int, nodeFunc func(string, int) error) {
	t.Helper()

	eg := new(errgroup.Group)
	relayAddr := relay.StartRelay(t.Context(), t)

	for n := range numNodes {
		eg.Go(func() error {
			return nodeFunc(relayAddr, n)
		})
	}

	require.NoError(t, eg.Wait())
}

// failNode cancels the other nodes and returns the node's failure as a wrapped error.
// It also logs the failure, since the errgroup surfaces only the first returned error.
// Note that require.FailNow (runtime.Goexit) must not be called from runProtocol goroutines.
func failNode(t *testing.T, cancel context.CancelFunc, n int, err error) error {
	t.Helper()
	t.Logf("Node %d failed: %v", n, err)
	cancel()

	return errors.Wrap(err, "run node protocol", z.Int("node", n))
}

func createDKGConfig(t *testing.T, relayAddr string) dkg.Config {
	t.Helper()

	return dkg.Config{
		ShutdownDelay: 3 * time.Second,
		Timeout:       time.Minute,
		P2P: p2p.Config{
			Relays:   []string{relayAddr},
			TCPAddrs: []string{testutil.AvailableAddr(t).String()},
		},
		Log: log.DefaultConfig(),
	}
}

func nodeDir(clusterDir string, i int) string {
	return fmt.Sprintf("%s/node%d", clusterDir, i)
}

func getNodeDirs(clusterDir string, numNodes int, skip ...int) []string {
	dirs := make([]string, 0, numNodes)
	for i := range numNodes {
		if slices.Contains(skip, i) {
			continue
		}

		dirs = append(dirs, nodeDir(clusterDir, i))
	}

	return dirs
}

func verifyClusterValidators(t *testing.T, numVals int, nodeDirs []string) {
	t.Helper()

	numNodes := len(nodeDirs)
	clusterSecrets := make([][]tbls.PrivateKey, numNodes)

	for i, ndir := range nodeDirs {
		lockFilePath := path.Join(ndir, clusterLockFile)
		lock, err := dkg.LoadAndVerifyClusterLock(t.Context(), lockFilePath, "", false)
		require.NoError(t, err, "nodeDir: %s", ndir)
		require.Len(t, lock.Operators, numNodes)
		require.Len(t, lock.Validators, numVals)

		secrets, err := dkg.LoadSecrets(path.Join(ndir, validatorKeysDir))
		require.NoError(t, err)
		require.Len(t, secrets, numVals)

		clusterSecrets[i] = secrets
	}

	data := []byte("test data")
	allSigs := make([]map[int]tbls.Signature, numVals)
	validatorPubKeys := make([]tbls.PublicKey, numVals)

	for valIdx := range numVals {
		sigsByIdx := make(map[int]tbls.Signature)

		for nodeIdx := range numNodes {
			sig, err := tbls.Sign(clusterSecrets[nodeIdx][valIdx], data)
			require.NoError(t, err)

			// Use 1-based share indices as production does
			sigsByIdx[nodeIdx+1] = sig
		}

		allSigs[valIdx] = sigsByIdx

		// Get the validator's full public key for verification
		lockFilePath := path.Join(nodeDirs[0], clusterLockFile)
		lock, err := dkg.LoadAndVerifyClusterLock(t.Context(), lockFilePath, "", false)
		require.NoError(t, err)

		validatorPubKeys[valIdx] = tbls.PublicKey(lock.Validators[valIdx].PubKey)
	}

	for valIdx := range numVals {
		// Use ThresholdAggregate (Lagrange interpolation) instead of simple Aggregate
		// to ensure share indices are correct - this is what production uses.
		aSig, err := tbls.ThresholdAggregate(allSigs[valIdx])
		require.NoError(t, err)

		err = tbls.Verify(validatorPubKeys[valIdx], data, aSig)
		require.NoError(t, err)
	}
}

func overridesPath(ndir string) string {
	return path.Join(ndir, "builder_registrations_overrides.json")
}

func getNodeIdxs(numNodes int) []int {
	idxs := make([]int, numNodes)
	for i := range idxs {
		idxs[i] = i
	}

	return idxs
}

// loadProposerConfig returns the config of the node's proposer config file.
func loadProposerConfig(t *testing.T, ndir string) proposerconfig.Config {
	t.Helper()

	lock, nodeIdx := loadLockAndNodeIdx(t, ndir)

	doc, err := proposerconfig.Load(proposerconfig.FilePath(ndir), lock, nodeIdx)
	require.NoError(t, err)

	return doc.Config
}

// loadLockAndNodeIdx returns the node's cluster lock and its index in it.
func loadLockAndNodeIdx(t *testing.T, ndir string) (cluster.Lock, cluster.NodeIdx) {
	t.Helper()

	lock, err := dkg.LoadAndVerifyClusterLock(t.Context(), path.Join(ndir, clusterLockFile), "", false)
	require.NoError(t, err)

	key, err := k1util.Load(p2p.KeyPath(ndir))
	require.NoError(t, err)

	peerID, err := p2p.PeerIDFromKey(key.PubKey())
	require.NoError(t, err)

	nodeIdx, err := lock.NodeIdx(peerID)
	require.NoError(t, err)

	return *lock, nodeIdx
}

// divergingProposerConfig returns config with a builder and a fee recipient diverging from the lock's.
func divergingProposerConfig(t *testing.T, lock cluster.Lock, builderURL string) proposerconfig.Config {
	t.Helper()

	fees := lock.FeeRecipientAddresses()
	fees[1] = "0x000000000000000000000000000000000000dead"

	cfg, err := proposerconfig.NewConfig(lock, fees, 36_000_000, &proposerconfig.Builder{
		MinBid:              "1",
		BuilderBoostFactor:  "90",
		MaxExecutionPayment: "2",
		Builders:            []proposerconfig.BuilderEntry{{URL: builderURL}},
	})
	require.NoError(t, err)

	return cfg
}

// writeProposerConfigs writes the config at revision to the given nodes' proposer config files,
// signed by all operators unless revision 0.
func writeProposerConfigs(t *testing.T, lock cluster.Lock, clusterDir string, nodes []int, revision uint64, cfg proposerconfig.Config) {
	t.Helper()

	doc := proposerconfig.Document{
		Version:  proposerconfig.Version,
		LockHash: lock.LockHash,
		Revision: revision,
		Config:   cfg,
	}

	if revision > 0 {
		for i := range lock.Operators {
			key, err := k1util.Load(p2p.KeyPath(nodeDir(clusterDir, i)))
			require.NoError(t, err)

			sig, err := proposerconfig.Sign(doc, key)
			require.NoError(t, err)

			doc.Signatures = append(doc.Signatures, proposerconfig.Signature{Operator: i, Signature: sig})
		}
	}

	require.NoError(t, proposerconfig.Verify(doc, lock))

	for _, n := range nodes {
		err := proposerconfig.Write(proposerconfig.FilePath(nodeDir(clusterDir, n)), doc, lock, cluster.NodeIdx{PeerIdx: n, ShareIdx: n + 1})
		require.NoError(t, err)
	}
}

// verifyCarriedProposerConfigs verifies each node's proposer config is signed by all operators of its new lock
// at revision 1 and carries the wanted config.
func verifyCarriedProposerConfigs(t *testing.T, nodeDirs []string, want proposerconfig.Config) {
	t.Helper()

	want, err := proposerconfig.Normalise(want)
	require.NoError(t, err)

	for _, ndir := range nodeDirs {
		lock, nodeIdx := loadLockAndNodeIdx(t, ndir)

		doc, err := proposerconfig.Load(proposerconfig.FilePath(ndir), lock, nodeIdx)
		require.NoError(t, err, "nodeDir: %s", ndir)
		require.NoError(t, proposerconfig.Verify(doc, lock), "nodeDir: %s", ndir)
		require.Equal(t, uint64(1), doc.Revision)
		require.Equal(t, getNodeIdxs(len(lock.Operators)), doc.SignerIndexes())

		got, err := proposerconfig.Normalise(doc.Config)
		require.NoError(t, err)
		require.Equal(t, want, got, "nodeDir: %s", ndir)
	}
}
