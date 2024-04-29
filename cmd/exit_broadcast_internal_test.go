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
		testRunBcastFullExitCmdFlow(t, false)
	})
	t.Run("main flow from file", func(t *testing.T) {
		t.Parallel()
		testRunBcastFullExitCmdFlow(t, true)
	})
	t.Run("config", Test_runBcastFullExitCmd_Config)
}

func testRunBcastFullExitCmdFlow(t *testing.T, fromFile bool) {
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

	for opIdx := 0; opIdx < operatorAmt; opIdx++ {
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

	eth2Cl, err := eth2Client(ctx, beaconMock.Address(), 10*time.Second)
	require.NoError(t, err)

	eth2Cl.SetForkVersion([4]byte(lock.ForkVersion))

	handler, addLockFiles := obolapimock.MockServer(false, eth2Cl)
	srv := httptest.NewServer(handler)
	addLockFiles(lock)
	defer srv.Close()

	writeAllLockData(t, root, operatorAmt, enrs, operatorShares, mBytes)

	for idx := 0; idx < operatorAmt; idx++ {
		baseDir := filepath.Join(root, fmt.Sprintf("op%d", idx))

		config := exitConfig{
			BeaconNodeURL:     beaconMock.Address(),
			ValidatorPubkey:   lock.Validators[0].PublicKeyHex(),
			PrivateKeyPath:    filepath.Join(baseDir, "charon-enr-private-key"),
			ValidatorKeysDir:  filepath.Join(baseDir, "validator_keys"),
			LockFilePath:      filepath.Join(baseDir, "cluster-lock.json"),
			PublishAddress:    srv.URL,
			ExitEpoch:         194048,
			BeaconNodeTimeout: 30 * time.Second,
		}

		require.NoError(t, runSignPartialExit(ctx, config), "operator index: %v", idx)
	}

	baseDir := filepath.Join(root, fmt.Sprintf("op%d", 0))

	config := exitConfig{
		BeaconNodeURL:     beaconMock.Address(),
		ValidatorPubkey:   lock.Validators[0].PublicKeyHex(),
		PrivateKeyPath:    filepath.Join(baseDir, "charon-enr-private-key"),
		ValidatorKeysDir:  filepath.Join(baseDir, "validator_keys"),
		LockFilePath:      filepath.Join(baseDir, "cluster-lock.json"),
		PublishAddress:    srv.URL,
		ExitEpoch:         194048,
		BeaconNodeTimeout: 30 * time.Second,
	}

	if fromFile {
		exit, err := exitFromObolAPI(ctx, lock.Validators[0].PublicKeyHex(), srv.URL, cl, enrs[0])
		require.NoError(t, err)

		exitBytes, err := json.Marshal(exit)
		require.NoError(t, err)

		exitPath := filepath.Join(baseDir, "exit.json")
		require.NoError(t, os.WriteFile(exitPath, exitBytes, 0o755))

		config.ExitFromFilePath = exitPath
	}

	require.NoError(t, runBcastFullExit(ctx, config))
}

func Test_runBcastFullExitCmd_Config(t *testing.T) {
	t.Parallel()
	type test struct {
		name                string
		noIdentity          bool
		noLock              bool
		badOAPIURL          bool
		badBeaconNodeURL    bool
		badValidatorAddr    bool
		badExistingExitPath bool
		errData             string
	}

	tests := []test{
		{
			name:       "No identity key",
			noIdentity: true,
			errData:    "could not load identity key",
		},
		{
			name:    "No lock",
			noLock:  true,
			errData: "could not load cluster-lock.json",
		},
		{
			name:       "Bad Obol API URL",
			badOAPIURL: true,
			errData:    "could not create obol api client",
		},
		{
			name:             "Bad beacon node URL",
			badBeaconNodeURL: true,
			errData:          "cannot create eth2 client for specified beacon node",
		},
		{
			name:             "Bad validator address",
			badValidatorAddr: true,
			errData:          "cannot convert validator pubkey to bytes",
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
		test := test
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

			for opIdx := 0; opIdx < operatorAmt; opIdx++ {
				for _, share := range keyShares {
					operatorShares[opIdx] = append(operatorShares[opIdx], share[opIdx])
				}
			}

			mBytes, err := json.Marshal(lock)
			require.NoError(t, err)

			writeAllLockData(t, root, operatorAmt, enrs, operatorShares, mBytes)

			for opIdx := 0; opIdx < operatorAmt; opIdx++ {
				del(t, test, root, opIdx)
			}

			bnURL := badStr

			if !test.badBeaconNodeURL {
				beaconMock, err := beaconmock.New()
				require.NoError(t, err)
				defer func() {
					require.NoError(t, beaconMock.Close())
				}()
				bnURL = beaconMock.Address()
			}

			oapiURL := badStr
			if !test.badOAPIURL {
				oapiURL = "https://api.obol.tech"
			}

			valAddr := badStr
			if !test.badValidatorAddr {
				valAddr = lock.Validators[0].PublicKeyHex()
			}

			baseDir := filepath.Join(root, "op0") // one operator is enough

			config := exitConfig{
				BeaconNodeURL:     bnURL,
				ValidatorPubkey:   valAddr,
				PrivateKeyPath:    filepath.Join(baseDir, "charon-enr-private-key"),
				ValidatorKeysDir:  filepath.Join(baseDir, "validator_keys"),
				LockFilePath:      filepath.Join(baseDir, "cluster-lock.json"),
				PublishAddress:    oapiURL,
				ExitEpoch:         0,
				BeaconNodeTimeout: 30 * time.Second,
			}

			if test.badExistingExitPath {
				path := filepath.Join(baseDir, "exit.json")
				require.NoError(t, os.WriteFile(path, []byte("bad"), 0o755))
				config.ExitFromFilePath = path
			}

			require.ErrorContains(t, runBcastFullExit(ctx, config), test.errData)
		})
	}
}
