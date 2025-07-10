// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
	"github.com/obolnetwork/charon/testutil/obolapimock"
)

func Test_runFetchExit(t *testing.T) {
	t.Parallel()
	t.Run("full flow", func(t *testing.T) {
		t.Parallel()
		testRunFetchExitFullFlow(t, false)
	})
	t.Run("full flow all", func(t *testing.T) {
		t.Parallel()
		testRunFetchExitFullFlow(t, true)
	})
	t.Run("bad out dir", Test_runFetchExitBadOutDir)
}

func testRunFetchExitFullFlow(t *testing.T, all bool) {
	t.Helper()

	ctx := context.Background()

	valAmt := 100
	operatorAmt := 4

	random := rand.New(rand.NewSource(int64(0)))

	lock, enrs, keyShares := cluster.NewForT(
		t,
		valAmt,
		operatorAmt,
		operatorAmt,
		0,
		random,
	)

	root := t.TempDir()

	operatorShares := make([][]tbls.PrivateKey, operatorAmt)

	for opIdx := range operatorAmt {
		for _, share := range keyShares {
			operatorShares[opIdx] = append(operatorShares[opIdx], share[opIdx])
		}
	}

	mBytes, err := json.Marshal(lock)
	require.NoError(t, err)

	validatorSet := beaconmock.ValidatorSet{}

	for idx, v := range lock.Validators {
		validatorSet[eth2p0.ValidatorIndex(idx)] = &eth2v1.Validator{
			Index:   eth2p0.ValidatorIndex(idx),
			Balance: 42,
			Status:  eth2v1.ValidatorStateActiveOngoing,
			Validator: &eth2p0.Validator{
				PublicKey:             eth2p0.BLSPubKey(v.PubKey),
				WithdrawalCredentials: testutil.RandomBytes32(),
			},
		}
	}

	beaconMock, err := beaconmock.New(
		beaconmock.WithValidatorSet(validatorSet),
	)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, beaconMock.Close())
	}()

	eth2Cl, err := eth2Client(ctx, []string{}, map[string]string{}, []string{beaconMock.Address()}, 10*time.Second, [4]byte(lock.ForkVersion))
	require.NoError(t, err)

	handler, addLockFiles := obolapimock.MockServer(false, eth2Cl)
	srv := httptest.NewServer(handler)

	addLockFiles(lock)

	defer srv.Close()

	writeAllLockData(t, root, operatorAmt, enrs, operatorShares, mBytes)

	for idx := range operatorAmt {
		baseDir := filepath.Join(root, fmt.Sprintf("op%d", idx))

		config := exitConfig{
			BeaconNodeEndpoints: []string{beaconMock.Address()},
			ValidatorPubkey:     lock.Validators[0].PublicKeyHex(),
			PrivateKeyPath:      filepath.Join(baseDir, "charon-enr-private-key"),
			ValidatorKeysDir:    filepath.Join(baseDir, "validator_keys"),
			LockFilePath:        filepath.Join(baseDir, "cluster-lock.json"),
			PublishAddress:      srv.URL,
			ExitEpoch:           194048,
			BeaconNodeTimeout:   30 * time.Second,
			PublishTimeout:      10 * time.Second,
			All:                 all,
		}

		require.NoError(t, runSignPartialExit(ctx, config), "operator index: %v", idx)
	}

	baseDir := filepath.Join(root, fmt.Sprintf("op%d", 0))

	config := exitConfig{
		ValidatorPubkey: lock.Validators[0].PublicKeyHex(),
		PrivateKeyPath:  filepath.Join(baseDir, "charon-enr-private-key"),
		LockFilePath:    filepath.Join(baseDir, "cluster-lock.json"),
		PublishAddress:  srv.URL,
		FetchedExitPath: root,
		PublishTimeout:  10 * time.Second,
		All:             all,
	}

	require.NoError(t, runFetchExit(ctx, config))

	exitFilePath := filepath.Join(root, fmt.Sprintf("exit-%s.json", lock.Validators[0].PublicKeyHex()))

	require.FileExists(t, exitFilePath)

	f, err := os.Open(exitFilePath)
	require.NoError(t, err)

	var finalExit eth2p0.SignedVoluntaryExit
	require.NoError(t, json.NewDecoder(f).Decode(&finalExit))

	require.NotEmpty(t, finalExit)
}

func Test_runFetchExitBadOutDir(t *testing.T) {
	t.Parallel()

	config := exitConfig{
		FetchedExitPath: "bad",
	}

	require.Error(t, runFetchExit(context.Background(), config))

	config = exitConfig{
		FetchedExitPath: "",
	}

	require.Error(t, runFetchExit(context.Background(), config))

	cantWriteDir := filepath.Join(t.TempDir(), "cantwrite")
	require.NoError(t, os.MkdirAll(cantWriteDir, 0o400))

	config = exitConfig{
		FetchedExitPath: cantWriteDir,
	}

	require.ErrorContains(t, runFetchExit(context.Background(), config), "permission denied")
}

func TestExitFetchCLI(t *testing.T) {
	tests := []struct {
		name        string
		expectedErr string
		flags       []string
	}{
		{
			name:        "check flags",
			expectedErr: "store exit path: stat 1: no such file or directory",
			flags: []string{
				"--publish-address=test",
				"--private-key-file=test",
				"--lock-file=test",
				"--validator-public-key=test",
				"--fetched-exit-path=1",
				"--publish-timeout=1ms",
				"--all=false",
				"--testnet-name=test",
				"--testnet-fork-version=test",
				"--testnet-chain-id=1",
				"--testnet-genesis-timestamp=1",
				"--testnet-capella-hard-fork=test",
			},
		},
		{
			name:        "no validator public key and not all",
			expectedErr: "validator-public-key must be specified when exiting single validator.",
			flags: []string{
				"--publish-address=test",
				"--private-key-file=test",
				"--lock-file=test",
				"--fetched-exit-path=1",
				"--publish-timeout=1ms",
				"--all=false",
				"--testnet-name=test",
				"--testnet-fork-version=test",
				"--testnet-chain-id=1",
				"--testnet-genesis-timestamp=1",
				"--testnet-capella-hard-fork=test",
			},
		},
		{
			name:        "validator public key and all",
			expectedErr: "validator-public-key should not be specified when all is, as it is obsolete and misleading.",
			flags: []string{
				"--publish-address=test",
				"--private-key-file=test",
				"--lock-file=test",
				"--validator-public-key=test",
				"--fetched-exit-path=1",
				"--publish-timeout=1ms",
				"--all=true",
				"--testnet-name=test",
				"--testnet-fork-version=test",
				"--testnet-chain-id=1",
				"--testnet-genesis-timestamp=1",
				"--testnet-capella-hard-fork=test",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := newExitCmd(newFetchExitCmd(runFetchExit))
			cmd.SetArgs(append([]string{"fetch"}, test.flags...))

			err := cmd.Execute()
			if test.expectedErr != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, test.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestFetchExitFullFlowNotActivated(t *testing.T) {
	ctx := context.Background()

	valAmt := 10
	operatorAmt := 4

	random := rand.New(rand.NewSource(int64(0)))

	lock, enrs, keyShares := cluster.NewForT(
		t,
		valAmt,
		operatorAmt,
		operatorAmt,
		0,
		random,
	)

	root := t.TempDir()

	operatorShares := make([][]tbls.PrivateKey, operatorAmt)

	for opIdx := range operatorAmt {
		for _, share := range keyShares {
			operatorShares[opIdx] = append(operatorShares[opIdx], share[opIdx])
		}
	}

	mBytes, err := json.Marshal(lock)
	require.NoError(t, err)

	validatorSet := beaconmock.ValidatorSet{}

	for idx, v := range lock.Validators {
		validatorSet[eth2p0.ValidatorIndex(idx)] = &eth2v1.Validator{
			Index:   eth2p0.ValidatorIndex(idx),
			Balance: 42,
			Status:  eth2v1.ValidatorStateActiveOngoing,
			Validator: &eth2p0.Validator{
				PublicKey:             eth2p0.BLSPubKey(v.PubKey),
				WithdrawalCredentials: testutil.RandomBytes32(),
			},
		}
	}

	beaconMock, err := beaconmock.New(
		beaconmock.WithValidatorSet(validatorSet),
	)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, beaconMock.Close())
	}()

	eth2Cl, err := eth2Client(ctx, []string{}, map[string]string{}, []string{beaconMock.Address()}, 10*time.Second, [4]byte(lock.ForkVersion))
	require.NoError(t, err)

	handler, addLockFiles := obolapimock.MockServer(false, eth2Cl)
	srv := httptest.NewServer(handler)

	addLockFiles(lock)

	defer srv.Close()

	writeAllLockData(t, root, operatorAmt, enrs, operatorShares, mBytes)

	for idxOp := range operatorAmt {
		// submit partial exits only for a subset
		for idxVal := range valAmt / 2 {
			baseDir := filepath.Join(root, fmt.Sprintf("op%d", idxOp))

			config := exitConfig{
				BeaconNodeEndpoints: []string{beaconMock.Address()},
				ValidatorPubkey:     lock.Validators[0].PublicKeyHex(),
				PrivateKeyPath:      filepath.Join(baseDir, "charon-enr-private-key"),
				ValidatorKeysDir:    filepath.Join(baseDir, "validator_keys"),
				LockFilePath:        filepath.Join(baseDir, "cluster-lock.json"),
				PublishAddress:      srv.URL,
				ExitEpoch:           194048,
				BeaconNodeTimeout:   30 * time.Second,
				PublishTimeout:      10 * time.Second,
			}
			config.ValidatorPubkey = lock.Validators[idxVal].PublicKeyHex()

			require.NoError(t, runSignPartialExit(ctx, config), "operator index: %v", idxOp)
		}
	}

	baseDir := filepath.Join(root, fmt.Sprintf("op%d", 0))

	config := exitConfig{
		ValidatorPubkey: lock.Validators[0].PublicKeyHex(),
		PrivateKeyPath:  filepath.Join(baseDir, "charon-enr-private-key"),
		LockFilePath:    filepath.Join(baseDir, "cluster-lock.json"),
		PublishAddress:  srv.URL,
		FetchedExitPath: root,
		PublishTimeout:  10 * time.Second,
		All:             true,
	}

	require.NoError(t, runFetchExit(ctx, config))

	for idxVal := range valAmt / 2 {
		exitFilePath := filepath.Join(root, fmt.Sprintf("exit-%s.json", lock.Validators[idxVal].PublicKeyHex()))

		require.FileExists(t, exitFilePath)

		f, err := os.Open(exitFilePath)
		require.NoError(t, err)

		var finalExit eth2p0.SignedVoluntaryExit
		require.NoError(t, json.NewDecoder(f).Decode(&finalExit))

		require.NotEmpty(t, finalExit)
	}
}
