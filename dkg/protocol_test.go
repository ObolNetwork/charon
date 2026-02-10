// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg_test

import (
	"bytes"
	"context"
	"fmt"
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
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cluster"
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
			LockFilePath:     path.Join(ndir, clusterLockFile),
			PrivateKeyPath:   p2p.KeyPath(ndir),
			ValidatorKeysDir: path.Join(ndir, validatorKeysDir),
			OutputDir:        nodeDir(dstClusterDir, n),
			RemovingENRs:     oldENRs,
		}

		err := dkg.RunRemoveOperatorsProtocol(ctx, removeConfig, dkgConfig)
		if err != nil {
			cancel()
			require.FailNowf(t, "Protocol failed", "Node %d failed: %v", n, err)
		}

		return err
	})

	verifyClusterValidators(t, numValidators, outputNodeDirs)
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
			LockFilePath:     path.Join(ndir, clusterLockFile),
			PrivateKeyPath:   p2p.KeyPath(ndir),
			ValidatorKeysDir: path.Join(ndir, validatorKeysDir),
			OutputDir:        nodeDir(dstClusterDir, n),
			RemovingENRs:     oldENRs,
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
			cancel()
			require.FailNowf(t, "Protocol failed", "Node %d failed: %v", n, err)
		}

		return err
	})

	verifyClusterValidators(t, numValidators, outputNodeDirs)
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
			LockFilePath:     path.Join(ndir, clusterLockFile),
			PrivateKeyPath:   p2p.KeyPath(ndir),
			ValidatorKeysDir: path.Join(ndir, validatorKeysDir),
			OutputDir:        nodeDir(dstClusterDir, n),
			NewENRs:          enrs,
		}

		err := dkg.RunAddOperatorsProtocol(ctx, addConfig, dkgConfig)
		if err != nil {
			cancel()
			require.FailNowf(t, "Protocol failed", "Node %d failed: %v", n, err)
		}

		return err
	})

	verifyClusterValidators(t, numValidators, getNodeDirs(dstClusterDir, totalNodes))
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

	// Create a separate directory for the new operator (since it's a different entity)
	newOpNodeDir := nodeDir(srcClusterDir, numNodes) // Create directory for new operator who doesn't have existing cluster data
	newOpEnr := createENR(t, newOpNodeDir)

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
			LockFilePath:     path.Join(ndir, clusterLockFile),
			PrivateKeyPath:   p2p.KeyPath(ndir),
			ValidatorKeysDir: path.Join(ndir, validatorKeysDir),
			OutputDir:        nodeDir(dstClusterDir, n),
			NewENR:           newOpEnr,
			OldENR:           lock.Operators[replacingIndex].ENR,
		}

		err := dkg.RunReplaceOperatorProtocol(ctx, replaceConfig, dkgConfig)
		if err != nil {
			cancel()
			require.FailNowf(t, "Protocol failed", "Node %d failed: %v", n, err)
		}

		return nil
	})

	verifyClusterValidators(t, numValidators, getNodeDirs(dstClusterDir, numNodes))
}

func TestRunReshareProtocol(t *testing.T) {
	const (
		numValidators = 3
		numNodes      = 7
		threshold     = 5
	)

	srcClusterDir := createTestCluster(t, numNodes, threshold, numValidators)
	dstClusterDir := t.TempDir()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	runProtocol(t, numNodes, func(relayAddr string, n int) error {
		dkgConfig := createDKGConfig(t, relayAddr)
		outputDir := nodeDir(dstClusterDir, n)
		dataDir := nodeDir(srcClusterDir, n)

		reshareConfig := dkg.ReshareConfig{
			DKGConfig:        dkgConfig,
			PrivateKeyPath:   p2p.KeyPath(dataDir),
			LockFilePath:     path.Join(dataDir, clusterLockFile),
			ValidatorKeysDir: path.Join(dataDir, validatorKeysDir),
			OutputDir:        outputDir,
		}

		err := dkg.RunReshareProtocol(ctx, reshareConfig)
		if err != nil {
			cancel()
			require.FailNowf(t, "Protocol failed", "Node %d failed: %v", n, err)
		}

		return err
	})

	verifyClusterValidators(t, numValidators, getNodeDirs(dstClusterDir, numNodes))
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

func createTestCluster(t *testing.T, numNodes, threshold, numValidators int) string {
	t.Helper()

	clusterDir := t.TempDir()

	args := []string{
		"create", "cluster",
		"--cluster-dir", clusterDir,
		"--nodes", strconv.Itoa(numNodes),
		"--threshold", strconv.Itoa(threshold),
		"--num-validators", strconv.Itoa(numValidators),
		"--network", eth2util.Holesky.Name,
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

func verifyClusterValidators(t *testing.T, numVals int, nodeDirs []string) { //nolint:unparam
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
