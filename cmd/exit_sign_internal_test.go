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
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
	"github.com/obolnetwork/charon/testutil/obolapimock"
)

//nolint:unparam // we mostly pass "4" for operatorAmt but we might change it later.
func writeAllLockData(
	t *testing.T,
	root string,
	operatorAmt int,
	enrs []*k1.PrivateKey,
	operatorShares [][]tbls.PrivateKey,
	manifestBytes []byte,
) {
	t.Helper()

	for opIdx := range operatorAmt {
		opID := fmt.Sprintf("op%d", opIdx)
		oDir := filepath.Join(root, opID)
		keysDir := filepath.Join(oDir, "validator_keys")
		manifestFile := filepath.Join(oDir, "cluster-lock.json")

		require.NoError(t, os.MkdirAll(oDir, 0o755))
		require.NoError(t, k1util.Save(enrs[opIdx], filepath.Join(oDir, "charon-enr-private-key")))

		require.NoError(t, os.MkdirAll(keysDir, 0o755))

		require.NoError(t, keystore.StoreKeysInsecure(operatorShares[opIdx], keysDir, keystore.ConfirmInsecureKeys))
		require.NoError(t, os.WriteFile(manifestFile, manifestBytes, 0o755))
	}
}

func Test_runSubmitPartialExit(t *testing.T) {
	t.Parallel()

	t.Run("main flow with bad pubkey", func(t *testing.T) {
		runSubmitPartialExitFlowTest(
			t,
			false,
			false,
			"test",
			0,
			"cannot convert validator pubkey to bytes",
		)
	})

	t.Run("main flow with pubkey not found in cluster lock", func(t *testing.T) {
		runSubmitPartialExitFlowTest(
			t,
			false,
			false,
			testutil.RandomEth2PubKey(t).String(),
			0,
			"validator not present in cluster lock",
		)
	})

	t.Run("main flow with validator index set not found in cluster lock", func(t *testing.T) {
		runSubmitPartialExitFlowTest(
			t,
			true,
			false,
			"",
			9999,
			"validator index not found in beacon node response",
		)
	})

	t.Run("main flow with expert mode with bad pubkey", func(t *testing.T) {
		runSubmitPartialExitFlowTest(
			t,
			true,
			true,
			"test",
			9999,
			"cannot convert validator pubkey to bytes",
		)
	})

	t.Run("main flow with expert mode with pubkey not found in cluster lock", func(t *testing.T) {
		runSubmitPartialExitFlowTest(
			t,
			true,
			true,
			testutil.RandomEth2PubKey(t).String(),
			9999,
			"validator not present in cluster lock",
		)
	})

	t.Run("main flow with pubkey", func(t *testing.T) {
		runSubmitPartialExitFlowTest(t, false, false, "", 0, "")
	})
	t.Run("main flow with validator index", func(t *testing.T) {
		runSubmitPartialExitFlowTest(t, true, false, "", 0, "")
	})
	t.Run("main flow with expert mode", func(t *testing.T) {
		runSubmitPartialExitFlowTest(t, true, true, "", 0, "")
	})

	t.Run("config", Test_runSubmitPartialExit_Config)
}

func runSubmitPartialExitFlowTest(t *testing.T, useValIdx bool, expertMode bool, valPubkey string, valIndex uint64, errString string) {
	t.Helper()
	t.Parallel()
	ctx := context.Background()

	ctx = log.WithCtx(ctx, z.Str("test_case", t.Name()))

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

	beaconMock, err := beaconmock.New(beaconmock.WithValidatorSet(validatorSet))
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

	index := uint64(0)
	pubkey := lock.Validators[0].PublicKeyHex()

	if valIndex != 0 {
		index = valIndex
	}

	if valPubkey != "" {
		pubkey = valPubkey
	}

	if expertMode {
		config.ValidatorIndex = index
		config.ValidatorIndexPresent = true
		config.ValidatorPubkey = pubkey
		config.ExpertMode = true
	} else {
		if useValIdx {
			config.ValidatorIndex = index
			config.ValidatorIndexPresent = true
		} else {
			config.ValidatorPubkey = pubkey
		}
	}

	if errString != "" {
		require.ErrorContains(t, runSignPartialExit(ctx, config), errString)
		return
	}

	require.NoError(t, runSignPartialExit(ctx, config))
}

func Test_runSubmitPartialExit_Config(t *testing.T) {
	t.Parallel()
	type test struct {
		name                   string
		noIdentity             bool
		noLock                 bool
		noKeystore             bool
		badOAPIURL             bool
		badBeaconNodeEndpoints bool
		badValidatorAddr       bool
		errData                string
	}

	tests := []test{
		{
			name:       "No identity key",
			noIdentity: true,
			errData:    "could not load identity key",
		},
		{
			name:    "No cluster lock",
			noLock:  true,
			errData: "could not load cluster-lock.json",
		},
		{
			name:       "No keystore",
			noKeystore: true,
			errData:    "could not load keystore",
		},
		{
			name:       "Bad Obol API URL",
			badOAPIURL: true,
			errData:    "could not create obol api client",
		},
		{
			name:                   "Bad beacon node URL",
			badBeaconNodeEndpoints: true,
			errData:                "cannot create eth2 client for specified beacon node",
		},
		{
			name:             "Bad validator address",
			badValidatorAddr: true,
			errData:          "cannot convert validator pubkey to bytes",
		},
	}

	del := func(t *testing.T, tc test, root string, opIdx int) {
		t.Helper()

		opID := fmt.Sprintf("op%d", opIdx)
		oDir := filepath.Join(root, opID)

		switch {
		case tc.noLock:
			require.NoError(t, os.RemoveAll(filepath.Join(oDir, "cluster-lock.json")))
		case tc.noKeystore:
			require.NoError(t, os.RemoveAll(filepath.Join(oDir, "validator_keys")))
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

			baseDir := filepath.Join(root, fmt.Sprintf("op%d", 0))

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
			}

			require.ErrorContains(t, runSignPartialExit(ctx, config), test.errData)
		})
	}
}
