// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http/httptest"
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

func Test_runDeleteExit(t *testing.T) {
	t.Parallel()
	t.Run("full flow", func(t *testing.T) {
		t.Parallel()
		testRunDeleteExitFullFlow(t, false)
	})
	t.Run("full flow all", func(t *testing.T) {
		t.Parallel()
		testRunDeleteExitFullFlow(t, true)
	})
}

func testRunDeleteExitFullFlow(t *testing.T, all bool) {
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
		t.Context(),
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

	idx := 1
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

	require.NoError(t, runDeleteExit(ctx, config))
}

func TestExitDeleteCLI(t *testing.T) {
	tests := []struct {
		name        string
		expectedErr string
		flags       []string
	}{
		{
			name:        "no validator public key and not all",
			expectedErr: "validator-public-key must be specified when exiting single validator.",
			flags: []string{
				"--publish-address=test",
				"--private-key-file=test",
				"--lock-file=test",
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
			cmd := newExitCmd(newDeleteExitCmd(runDeleteExit))
			cmd.SetArgs(append([]string{"delete"}, test.flags...))

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
