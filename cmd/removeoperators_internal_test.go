// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/dkg"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/relay"
)

func TestRunRemoveOperators(t *testing.T) {
	const (
		oldN    = 7
		oldT    = 5
		newN    = 4
		numVals = 3
	)

	clusterDir := t.TempDir()

	// This test creates a solo cluster 7/5, then remove-operators removes 3 old operators.
	conf := clusterConfig{
		ClusterDir:        clusterDir,
		Name:              "test_cluster",
		NumNodes:          oldN,
		Threshold:         oldT,
		NumDVs:            numVals,
		Network:           eth2util.Holesky.Name,
		TargetGasLimit:    36000000,
		FeeRecipientAddrs: []string{feeRecipientAddr, feeRecipientAddr, feeRecipientAddr},
		WithdrawalAddrs:   []string{feeRecipientAddr, feeRecipientAddr, feeRecipientAddr},
	}

	var buf bytes.Buffer

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	err := runCreateCluster(ctx, &buf, conf)
	require.NoError(t, err)

	entries, err := os.ReadDir(conf.ClusterDir)
	require.NoError(t, err)
	require.Len(t, entries, oldN)

	// Creating new nodes with just ENRs and lock files.
	oldENRs := make([]string, oldN-newN)
	for i := range oldENRs {
		ndir := nodeDir(conf.ClusterDir, i)
		key, err := p2p.LoadPrivKey(ndir)
		require.NoError(t, err)

		er, err := enr.New(key)
		require.NoError(t, err)

		oldENRs[i] = er.String()
	}

	dstDir := t.TempDir()
	relayAddr := relay.StartRelay(ctx, t)

	var (
		eg       errgroup.Group
		nodeDirs []string
	)

	for i := range oldN {
		config := dkg.RemoveOperatorsConfig{
			OutputDir: nodeDir(dstDir, i),
			OldENRs:   oldENRs,
		}

		dkgConfig := dkg.Config{
			DataDir: nodeDir(conf.ClusterDir, i),
			P2P: p2p.Config{
				Relays:   []string{relayAddr},
				TCPAddrs: []string{testutil.AvailableAddr(t).String()},
			},
			Log:           log.DefaultConfig(),
			ShutdownDelay: time.Second,
			Timeout:       30 * time.Second,
			NoVerify:      true,
		}
		if i >= len(oldENRs) {
			nodeDirs = append(nodeDirs, config.OutputDir)
		}

		eg.Go(func() error {
			peerCtx := log.WithCtx(ctx, z.Int("peer_index", i))
			return runRemoveOperators(peerCtx, config, dkgConfig)
		})
	}

	err = eg.Wait()
	testutil.SkipIfBindErr(t, err)
	testutil.RequireNoError(t, err)

	verifyClusterValidators(t, numVals, nodeDirs)
}

func TestNewRemoveOperatorsCmd(t *testing.T) {
	cmd := newRemoveOperatorsCmd(runRemoveOperators)
	require.NotNil(t, cmd)
	require.Equal(t, "remove-operators", cmd.Use)
	require.Equal(t, "Remove operators from an existing distributed validator cluster", cmd.Short)
	require.Empty(t, cmd.Flags().Args())
}

func TestValidateRemoveOperatorsConfig(t *testing.T) {
	realDir := t.TempDir()
	err := os.WriteFile(filepath.Join(realDir, clusterLockFile), []byte("{}"), 0o444)
	require.NoError(t, err)

	tests := []struct {
		name      string
		cmdConfig dkg.RemoveOperatorsConfig
		dkgConfig dkg.Config
		numOps    int
		errMsg    string
	}{
		{
			name: "missing old operator enrs",
			cmdConfig: dkg.RemoveOperatorsConfig{
				OutputDir: ".",
			},
			errMsg: "old-operator-enrs is required",
		},
		{
			name: "data dir is required",
			cmdConfig: dkg.RemoveOperatorsConfig{
				OutputDir: ".",
				OldENRs:   []string{"enr:-IS4QH"},
			},
			errMsg: "data-dir is required",
		},
		{
			name: "missing lock file",
			cmdConfig: dkg.RemoveOperatorsConfig{
				OutputDir: ".",
				OldENRs:   []string{"enr:-IS4QH"},
			},
			dkgConfig: dkg.Config{
				DataDir: ".",
			},
			errMsg: "data-dir must contain a cluster-lock.json file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRemoveOperatorsConfig(&tt.cmdConfig, &tt.dkgConfig)
			if tt.errMsg != "" {
				require.Equal(t, tt.errMsg, err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
