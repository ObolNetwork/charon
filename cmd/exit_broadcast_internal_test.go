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
	"github.com/obolnetwork/charon/cluster/manifest"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
	"github.com/obolnetwork/charon/testutil/obolapimock"
)

const badStr = "bad"

func Test_runBcastFullExitCmd(t *testing.T) {
	t.Parallel()
	t.Run("main flow from api", func(t *testing.T) {
		t.Parallel()
		testRunBcastFullExitCmdFlow(t, false, false)
	})
	t.Run("main flow from file", func(t *testing.T) {
		t.Parallel()
		testRunBcastFullExitCmdFlow(t, true, false)
	})
	t.Run("main flow from api for all", func(t *testing.T) {
		t.Parallel()
		testRunBcastFullExitCmdFlow(t, false, true)
	})
	t.Run("main flow from file for all", func(t *testing.T) {
		t.Parallel()
		testRunBcastFullExitCmdFlow(t, true, true)
	})
	t.Run("main flow from api for all with already exited validator", func(t *testing.T) {
		t.Parallel()
		testRunBcastFullExitCmdFlow(t, false, false)
		testRunBcastFullExitCmdFlow(t, false, true)
	})
	t.Run("main flow from file for all with already exited validator", func(t *testing.T) {
		t.Parallel()
		testRunBcastFullExitCmdFlow(t, true, false)
		testRunBcastFullExitCmdFlow(t, true, true)
	})
	t.Run("config", Test_runBcastFullExitCmd_Config)
}

func testRunBcastFullExitCmdFlow(t *testing.T, fromFile bool, all bool) {
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

	dag, err := manifest.NewDAGFromLockForT(t, lock)
	require.NoError(t, err)
	cl, err := manifest.Materialise(dag)
	require.NoError(t, err)

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
		beaconmock.WithEndpoint("/eth/v1/beacon/pool/voluntary_exits", ""),
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
			PrivateKeyPath:      filepath.Join(baseDir, "charon-enr-private-key"),
			ValidatorKeysDir:    filepath.Join(baseDir, "validator_keys"),
			LockFilePath:        filepath.Join(baseDir, "cluster-lock.json"),
			PublishAddress:      srv.URL,
			ExitEpoch:           194048,
			BeaconNodeTimeout:   30 * time.Second,
			PublishTimeout:      10 * time.Second,
		}

		if all {
			config.All = all
		} else {
			config.ValidatorPubkey = lock.Validators[0].PublicKeyHex()
		}

		require.NoError(t, runSignPartialExit(ctx, config), "operator index: %v", idx)
	}

	baseDir := filepath.Join(root, fmt.Sprintf("op%d", 0))

	config := exitConfig{
		BeaconNodeEndpoints: []string{beaconMock.Address()},
		PrivateKeyPath:      filepath.Join(baseDir, "charon-enr-private-key"),
		ValidatorKeysDir:    filepath.Join(baseDir, "validator_keys"),
		LockFilePath:        filepath.Join(baseDir, "cluster-lock.json"),
		PublishAddress:      srv.URL,
		ExitEpoch:           194048,
		BeaconNodeTimeout:   30 * time.Second,
		PublishTimeout:      10 * time.Second,
	}

	if all {
		config.All = all
	} else {
		config.ValidatorPubkey = lock.Validators[0].PublicKeyHex()
	}

	if fromFile {
		if all {
			for _, validator := range lock.Validators {
				validatorPublicKey := validator.PublicKeyHex()
				exit, err := exitFromObolAPI(ctx, validatorPublicKey, srv.URL, 10*time.Second, cl, enrs[0])
				require.NoError(t, err)

				exitBytes, err := json.Marshal(exit)
				require.NoError(t, err)

				exitPath := filepath.Join(baseDir, fmt.Sprintf("exit-%s.json", validatorPublicKey))
				require.NoError(t, os.WriteFile(exitPath, exitBytes, 0o755))
			}

			config.ExitFromFileDir = baseDir
		} else {
			validatorPublicKey := lock.Validators[0].PublicKeyHex()
			exit, err := exitFromObolAPI(ctx, validatorPublicKey, srv.URL, 10*time.Second, cl, enrs[0])
			require.NoError(t, err)

			exitBytes, err := json.Marshal(exit)
			require.NoError(t, err)

			exitPath := filepath.Join(baseDir, fmt.Sprintf("exit-%s.json", validatorPublicKey))
			require.NoError(t, os.WriteFile(exitPath, exitBytes, 0o755))

			config.ExitFromFilePath = exitPath
		}
	}

	require.NoError(t, runBcastFullExit(ctx, config))
}

func Test_runBcastFullExitCmd_Config(t *testing.T) {
	t.Parallel()

	type test struct {
		name                   string
		noIdentity             bool
		noLock                 bool
		badOAPIURL             bool
		badBeaconNodeEndpoints bool
		badValidatorAddr       bool
		badExistingExitPath    bool
		errData                string
		all                    bool
	}

	tests := []test{
		{
			name:       "No identity key",
			noIdentity: true,
			errData:    "load identity key",
		},
		{
			name:    "No lock",
			noLock:  true,
			errData: "load cluster lock",
		},
		{
			name:       "Bad Obol API URL",
			badOAPIURL: true,
			errData:    "create Obol API client",
		},
		{
			name:                   "Bad beacon node URLs",
			badBeaconNodeEndpoints: true,
			errData:                "create eth2 client for specified beacon node",
		},
		{
			name:             "Bad validator address",
			badValidatorAddr: true,
			errData:          "validator pubkey to bytes",
		},
		{
			name:                "Bad existing exit file",
			badExistingExitPath: true,
			errData:             "invalid signed exit message",
		},
	}

	del := func(t *testing.T, tc test, root string, opIdx int) {
		t.Helper()

		opID := fmt.Sprintf("op%d", opIdx)
		oDir := filepath.Join(root, opID)

		switch {
		case tc.noLock:
			require.NoError(t, os.RemoveAll(filepath.Join(oDir, "cluster-lock.json")))
		case tc.noIdentity:
			require.NoError(t, os.RemoveAll(filepath.Join(oDir, "charon-enr-private-key")))
		}
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

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

			writeAllLockData(t, root, operatorAmt, enrs, operatorShares, mBytes)

			for opIdx := range operatorAmt {
				del(t, test, root, opIdx)
			}

			bnURL := badStr

			if !test.badBeaconNodeEndpoints {
				beaconMock, err := beaconmock.New()
				require.NoError(t, err)

				defer func() {
					require.NoError(t, beaconMock.Close())
				}()

				bnURL = beaconMock.Address()
			}

			oapiURL := badStr
			if !test.badOAPIURL {
				oapiURL = "https://api.obol.tech/v1"
			}

			valAddr := badStr
			if !test.badValidatorAddr {
				valAddr = lock.Validators[0].PublicKeyHex()
			}

			baseDir := filepath.Join(root, "op0") // one operator is enough

			config := exitConfig{
				BeaconNodeEndpoints: []string{bnURL},
				ValidatorPubkey:     valAddr,
				PrivateKeyPath:      filepath.Join(baseDir, "charon-enr-private-key"),
				ValidatorKeysDir:    filepath.Join(baseDir, "validator_keys"),
				LockFilePath:        filepath.Join(baseDir, "cluster-lock.json"),
				PublishAddress:      oapiURL,
				ExitEpoch:           0,
				BeaconNodeTimeout:   30 * time.Second,
				PublishTimeout:      10 * time.Second,
				All:                 test.all,
			}

			if test.badExistingExitPath {
				path := filepath.Join(baseDir, fmt.Sprintf("exit-%s.json", lock.Validators[0].PublicKeyHex()))
				require.NoError(t, os.WriteFile(path, []byte("bad"), 0o755))
				config.ExitFromFilePath = path
			}

			require.ErrorContains(t, runBcastFullExit(ctx, config), test.errData)
		})
	}
}

func TestExitBroadcastCLI(t *testing.T) {
	tests := []struct {
		name        string
		expectedErr string

		flags []string
	}{
		{
			name:        "check flags",
			expectedErr: "load identity key: read private key from disk: open test: no such file or directory",
			flags: []string{
				"--publish-address=test",
				"--private-key-file=test",
				"--lock-file=test",
				"--validator-keys-dir=test",
				"--exit-epoch=1",
				"--validator-public-key=test", // single exit
				"--beacon-node-endpoints=test1,test2",
				"--exit-from-file=test", // single exit
				"--beacon-node-timeout=1ms",
				"--publish-timeout=1ms",
				"--all=false", // single exit
				"--testnet-name=test",
				"--testnet-fork-version=test",
				"--testnet-chain-id=1",
				"--testnet-genesis-timestamp=1",
				"--testnet-capella-hard-fork=test",
			},
		},
		{
			name:        "check flags all",
			expectedErr: "load identity key: read private key from disk: open test: no such file or directory",
			flags: []string{
				"--publish-address=test",
				"--private-key-file=test",
				"--lock-file=test",
				"--validator-keys-dir=test", // exit all
				"--exit-epoch=1",
				"--beacon-node-endpoints=test1,test2",
				"--exit-from-dir=test",
				"--beacon-node-timeout=1ms",
				"--publish-timeout=1ms",
				"--all", // exit all
				"--testnet-name=test",
				"--testnet-fork-version=test",
				"--testnet-chain-id=1",
				"--testnet-genesis-timestamp=1",
				"--testnet-capella-hard-fork=test",
			},
		},
		{
			name:        "check flags all",
			expectedErr: "load identity key: read private key from disk: open test: no such file or directory",
			flags: []string{
				"--publish-address=test",
				"--private-key-file=test",
				"--lock-file=test",
				"--validator-keys-dir=test", // exit all
				"--exit-epoch=1",
				"--beacon-node-endpoints=test1,test2",
				"--exit-from-dir=test",
				"--beacon-node-timeout=1ms",
				"--publish-timeout=1ms",
				"--all", // exit all
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
			cmd := newExitCmd(newBcastFullExitCmd(runBcastFullExit))
			cmd.SetArgs(append([]string{"broadcast"}, test.flags...))

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

func TestExitBcastFullExitNotActivated(t *testing.T) {
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
		beaconmock.WithEndpoint("/eth/v1/beacon/pool/voluntary_exits", ""),
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
		BeaconNodeEndpoints: []string{beaconMock.Address()},
		PrivateKeyPath:      filepath.Join(baseDir, "charon-enr-private-key"),
		ValidatorKeysDir:    filepath.Join(baseDir, "validator_keys"),
		LockFilePath:        filepath.Join(baseDir, "cluster-lock.json"),
		PublishAddress:      srv.URL,
		ExitEpoch:           194048,
		BeaconNodeTimeout:   30 * time.Second,
		PublishTimeout:      10 * time.Second,
	}

	// exit all and do not fail on non-existing keys
	config.All = true

	require.NoError(t, runBcastFullExit(ctx, config))
}
