// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/eth1wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/relay"
)

func TestRunAddValidators(t *testing.T) {
	// This test creates a solo cluster with all charon data for all nodes.
	// Then it runs add-validators on each node in parallel to add 2 validators per node.
	conf := clusterConfig{
		ClusterDir:        t.TempDir(),
		Name:              "test_cluster",
		NumNodes:          4,
		Threshold:         3,
		NumDVs:            3,
		Network:           eth2util.Holesky.Name,
		TargetGasLimit:    36000000,
		FeeRecipientAddrs: []string{feeRecipientAddr, feeRecipientAddr, feeRecipientAddr},
		WithdrawalAddrs:   []string{feeRecipientAddr, feeRecipientAddr, feeRecipientAddr},
	}

	var buf bytes.Buffer

	err := runCreateCluster(t.Context(), &buf, conf)
	require.NoError(t, err)

	entries, err := os.ReadDir(conf.ClusterDir)
	require.NoError(t, err)
	require.Len(t, entries, 4)

	dstClusterDir := t.TempDir()
	relayAddr := relay.StartRelay(t.Context(), t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var eg errgroup.Group

	for i := 0; i < conf.NumNodes; i++ {
		addConf := addValidatorsConfig{
			SrcDir:            nodeDir(conf.ClusterDir, i),
			DstDir:            nodeDir(dstClusterDir, i),
			NumValidators:     2,
			WithdrawalAddrs:   []string{feeRecipientAddr, feeRecipientAddr},
			FeeRecipientAddrs: []string{feeRecipientAddr, feeRecipientAddr},
			DKG: dkg.Config{
				P2P: p2p.Config{
					Relays:   []string{relayAddr},
					TCPAddrs: []string{testutil.AvailableAddr(t).String()},
				},
				Log:            log.DefaultConfig(),
				ShutdownDelay:  1 * time.Second,
				PublishTimeout: 30 * time.Second,
				Timeout:        8 * time.Second,
				NoVerify:       true,
			},
		}

		eg.Go(func() error {
			peerCtx := log.WithCtx(ctx, z.Int("peer_index", i))

			err := runAddValidators(peerCtx, addConf)
			if err != nil {
				cancel()
			}

			return err
		})

		time.Sleep(time.Millisecond * 100)
	}

	err = eg.Wait()
	testutil.SkipIfBindErr(t, err)
	testutil.RequireNoError(t, err)

	for n := 0; n < conf.NumNodes; n++ {
		nd := nodeDir(dstClusterDir, n)
		require.True(t, app.FileExists(nd))
		require.True(t, app.FileExists(filepath.Join(nd, clusterLockFile)))
		require.True(t, app.FileExists(filepath.Join(nd, validatorKeysSubDir)))

		keyFiles, err := os.ReadDir(filepath.Join(nd, validatorKeysSubDir))
		require.NoError(t, err)
		require.Len(t, keyFiles, 10) // 5 validators * two files per key

		var lock cluster.Lock

		lockFilePath := filepath.Join(nd, clusterLockFile)
		lockFile, err := os.ReadFile(lockFilePath)
		require.NoError(t, err)
		err = json.Unmarshal(lockFile, &lock)
		require.NoError(t, err)

		require.Equal(t, 5, lock.NumValidators)
		require.Len(t, lock.Validators, 5)

		err = lock.VerifyHashes()
		require.NoError(t, err)
		err = lock.VerifySignatures(eth1wrap.NewDefaultEthClientRunner(""))
		require.NoError(t, err)
	}
}

func TestValidateConfigAddValidators(t *testing.T) {
	realDir := t.TempDir()
	err := os.WriteFile(filepath.Join(realDir, clusterLockFile), []byte("{}"), 0o444)
	require.NoError(t, err)

	tests := []struct {
		name   string
		conf   addValidatorsConfig
		numOps int
		errMsg string
	}{
		{
			name: "insufficient validators",
			conf: addValidatorsConfig{
				NumValidators: 0,
			},
			errMsg: "num-validators must be greater than 0",
		},
		{
			name: "dst dir is required",
			conf: addValidatorsConfig{
				DstDir:        "",
				NumValidators: 1,
			},
			errMsg: "dst-dir is required",
		},
		{
			name: "src dir is required",
			conf: addValidatorsConfig{
				DstDir:        ".",
				SrcDir:        "",
				NumValidators: 1,
			},
			errMsg: "src-dir is required",
		},
		{
			name: "missing lock file",
			conf: addValidatorsConfig{
				SrcDir:        ".",
				DstDir:        ".",
				NumValidators: 1,
			},
			errMsg: "src-dir must contain a cluster-lock.json file",
		},
		{
			name: "addrs length mismatch",
			conf: addValidatorsConfig{
				SrcDir:            realDir,
				DstDir:            ".",
				NumValidators:     1,
				WithdrawalAddrs:   []string{feeRecipientAddr, feeRecipientAddr},
				FeeRecipientAddrs: []string{feeRecipientAddr},
			},
			errMsg: "mismatching --num-validators and --withdrawal-addresses",
		},
		{
			name: "single addr for all validators",
			conf: addValidatorsConfig{
				SrcDir:            realDir,
				DstDir:            ".",
				NumValidators:     2,
				WithdrawalAddrs:   []string{feeRecipientAddr},
				FeeRecipientAddrs: []string{feeRecipientAddr},
			},
		},
		{
			name: "count and addrs mismatch",
			conf: addValidatorsConfig{
				SrcDir:            realDir,
				DstDir:            ".",
				NumValidators:     2,
				WithdrawalAddrs:   []string{feeRecipientAddr, feeRecipientAddr, feeRecipientAddr},
				FeeRecipientAddrs: []string{feeRecipientAddr, feeRecipientAddr, feeRecipientAddr},
			},
			errMsg: "mismatching --num-validators and --fee-recipient-addresses",
		},
		{
			name: "multiple addrs for multiple validators",
			conf: addValidatorsConfig{
				SrcDir:            realDir,
				DstDir:            ".",
				NumValidators:     2,
				WithdrawalAddrs:   []string{feeRecipientAddr, feeRecipientAddr},
				FeeRecipientAddrs: []string{feeRecipientAddr, feeRecipientAddr},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(&tt.conf)
			if tt.errMsg != "" {
				require.Equal(t, tt.errMsg, err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestVerifyLock(t *testing.T) {
	b, err := os.ReadFile("testdata/test_cluster_lock.json")
	require.NoError(t, err)

	var lock cluster.Lock

	err = json.Unmarshal(b, &lock)
	require.NoError(t, err)

	err = verifyLock(t.Context(), lock, dkg.Config{NoVerify: true})
	require.NoError(t, err)

	err = verifyLock(t.Context(), lock, dkg.Config{NoVerify: false})
	require.NoError(t, err)
}
