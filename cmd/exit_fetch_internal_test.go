// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

	eth2Cl, err := eth2Client(ctx, []string{beaconMock.Address()}, 10*time.Second, [4]byte(lock.ForkVersion))
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

		publishAddress          string
		privateKeyPath          string
		lockFilePath            string
		validatorPubkey         string
		all                     string
		fetchedExitPath         string
		publishTimeout          string
		testnetName             string
		testnetForkVersion      string
		testnetChainID          string
		testnetGenesisTimestamp string
		testnetCapellaHardFork  string
	}{
		{
			name:        "check flags",
			expectedErr: "store exit path: stat 1: no such file or directory",

			publishAddress:          "--publish-address=test",
			privateKeyPath:          "--private-key-file=test",
			lockFilePath:            "--lock-file=test",
			validatorPubkey:         "--validator-public-key=test",
			fetchedExitPath:         "--fetched-exit-path=1",
			publishTimeout:          "--publish-timeout=1ms",
			all:                     "--all=false",
			testnetName:             "--testnet-name=test",
			testnetForkVersion:      "--testnet-fork-version=test",
			testnetChainID:          "--testnet-chain-id=1",
			testnetGenesisTimestamp: "--testnet-genesis-timestamp=1",
			testnetCapellaHardFork:  "--testnet-capella-hard-fork=test",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := newExitCmd(newFetchExitCmd(runFetchExit))
			cmd.SetArgs([]string{
				"fetch",
				test.publishAddress,
				test.privateKeyPath,
				test.lockFilePath,
				test.validatorPubkey,
				test.fetchedExitPath,
				test.publishTimeout,
				test.all,
				test.testnetName,
				test.testnetForkVersion,
				test.testnetChainID,
				test.testnetGenesisTimestamp,
				test.testnetCapellaHardFork,
			})

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
