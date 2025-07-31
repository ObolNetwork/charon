// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
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
	"github.com/obolnetwork/charon/eth2util/deposit"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/relay"
)

func TestRunAddValidators(t *testing.T) {
	// This test creates a solo cluster with all charon data for all nodes.
	// Then it runs add-validators on each node in parallel to add 2 validators per node.
	// Two sub-tests are run: with the `--unverified` flag and without.
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

	relayAddr := relay.StartRelay(t.Context(), t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	const testAuthToken = "test-auth-token"

	var allReceivedKeystores atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearerAuthToken := strings.Split(r.Header.Get("Authorization"), " ")
		require.Equal(t, bearerAuthToken[0], "Bearer")
		require.Equal(t, bearerAuthToken[1], testAuthToken)

		allReceivedKeystores.Add(1)
	}))
	defer srv.Close()

	runAddCommand := func(dstDir string, unverified bool) {
		var eg errgroup.Group

		for i := 0; i < conf.NumNodes; i++ {
			addConf := addValidatorsConfig{
				SrcDir:            nodeDir(conf.ClusterDir, i),
				DstDir:            nodeDir(dstDir, i),
				NumValidators:     2,
				WithdrawalAddrs:   []string{feeRecipientAddr, feeRecipientAddr},
				FeeRecipientAddrs: []string{feeRecipientAddr, feeRecipientAddr},
				Unverified:        unverified,
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

			if unverified {
				err = os.RemoveAll(filepath.Join(nodeDir(conf.ClusterDir, i), validatorKeysSubDir))
				require.NoError(t, err)

				addConf.DKG.KeymanagerAddr = srv.URL
				addConf.DKG.KeymanagerAuthToken = testAuthToken
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
	}

	verifyAddCommandResults := func(dstDir string, unverified bool) {
		for n := 0; n < conf.NumNodes; n++ {
			nd := nodeDir(dstDir, n)
			require.True(t, app.FileExists(nd))
			require.True(t, app.FileExists(filepath.Join(nd, clusterLockFile)))

			if !unverified {
				require.True(t, app.FileExists(filepath.Join(nd, validatorKeysSubDir)))

				keyFiles, err := os.ReadDir(filepath.Join(nd, validatorKeysSubDir))
				require.NoError(t, err)

				require.Len(t, keyFiles, 10) // 5 total validators * two files per key
			} else {
				require.EqualValues(t, 4, allReceivedKeystores.Load())
			}

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

			if !unverified {
				err = lock.VerifySignatures(eth1wrap.NewDefaultEthClientRunner(""))
				require.NoError(t, err)
			}

			dd, err := deposit.ReadDepositDataFiles(nd)
			require.NoError(t, err)
			require.Len(t, dd, 2) // two default amounts: 1eth and 32eth
			require.Len(t, dd[0], lock.NumValidators)
			require.Len(t, dd[1], lock.NumValidators)
		}
	}

	t.Run("add validators without unverified flag", func(t *testing.T) {
		dir := t.TempDir()
		runAddCommand(dir, false)
		verifyAddCommandResults(dir, false)
	})

	t.Run("add validators with unverified flag", func(t *testing.T) {
		dir := t.TempDir()
		runAddCommand(dir, true)
		verifyAddCommandResults(dir, true)
	})
}

func TestValidateConfigAddValidators(t *testing.T) {
	realDir := t.TempDir()
	err := os.WriteFile(filepath.Join(realDir, clusterLockFile), []byte("{}"), 0o444)
	require.NoError(t, err)

	validatorKeysDir := filepath.Join(realDir, validatorKeysSubDir)
	err = app.CreateNewEmptyDir(validatorKeysDir)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(validatorKeysDir, "keystore-0.json"), []byte("{}"), 0o444)
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
			name: "both --unverified and --publish flags",
			conf: addValidatorsConfig{
				SrcDir:            realDir,
				DstDir:            ".",
				NumValidators:     2,
				Unverified:        true,
				WithdrawalAddrs:   []string{feeRecipientAddr, feeRecipientAddr, feeRecipientAddr},
				FeeRecipientAddrs: []string{feeRecipientAddr, feeRecipientAddr, feeRecipientAddr},
				DKG: dkg.Config{
					Publish: true,
				},
			},
			errMsg: "the --unverified flag cannot be used when the --publish flag is set",
		},
		{
			name: "both --unverified flag for non empty validator_keys dir",
			conf: addValidatorsConfig{
				SrcDir:            realDir,
				DstDir:            ".",
				NumValidators:     2,
				Unverified:        true,
				WithdrawalAddrs:   []string{feeRecipientAddr, feeRecipientAddr, feeRecipientAddr},
				FeeRecipientAddrs: []string{feeRecipientAddr, feeRecipientAddr, feeRecipientAddr},
			},
			errMsg: "the --unverified flag cannot be used when the validator_keys directory is present",
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
			err := validateConfig(t.Context(), &tt.conf)
			if tt.errMsg != "" {
				require.Equal(t, tt.errMsg, err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}

	t.Run("empty validator_keys dir", func(t *testing.T) {
		srcDir := t.TempDir()
		err := os.WriteFile(filepath.Join(srcDir, clusterLockFile), []byte("{}"), 0o444)
		require.NoError(t, err)

		cfg := addValidatorsConfig{
			SrcDir:            srcDir,
			DstDir:            ".",
			NumValidators:     2,
			WithdrawalAddrs:   []string{feeRecipientAddr, feeRecipientAddr},
			FeeRecipientAddrs: []string{feeRecipientAddr, feeRecipientAddr},
		}

		err = validateConfig(t.Context(), &cfg)
		require.Equal(t, "src-dir must contain a non-empty validator_keys directory, or the --unverified flag must be set", err.Error())

		validatorKeysDir := filepath.Join(srcDir, validatorKeysSubDir)
		err = app.CreateNewEmptyDir(validatorKeysDir)
		require.NoError(t, err)

		err = validateConfig(t.Context(), &cfg)
		require.Equal(t, "src-dir must contain a non-empty validator_keys directory, or the --unverified flag must be set", err.Error())

		cfg.Unverified = true
		err = validateConfig(t.Context(), &cfg)
		require.Equal(t, "the --keymanager flag is required when the validator_keys directory is empty", err.Error())

		cfg.DKG.KeymanagerAddr = "http://localhost:1234"
		err = validateConfig(t.Context(), &cfg)
		require.NoError(t, err)
	})
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
