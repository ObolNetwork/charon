// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
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
)

func Test_runListActiveVals(t *testing.T) {
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

	baseDir := filepath.Join(root, fmt.Sprintf("op%d", 0))

	config := exitConfig{
		BeaconNodeEndpoints: []string{beaconMock.Address()},
		PrivateKeyPath:      filepath.Join(baseDir, "charon-enr-private-key"),
		ValidatorKeysDir:    filepath.Join(baseDir, "validator_keys"),
		LockFilePath:        filepath.Join(baseDir, "cluster-lock.json"),
		PlaintextOutput:     true,
		BeaconNodeTimeout:   30 * time.Second,
	}

	require.NoError(t, runListActiveValidatorsCmd(ctx, config))
}

func Test_listActiveVals(t *testing.T) {
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

	t.Run("all validators in the cluster are active", func(t *testing.T) {
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

		baseDir := filepath.Join(root, fmt.Sprintf("op%d", 0))

		config := exitConfig{
			BeaconNodeEndpoints: []string{beaconMock.Address()},
			PrivateKeyPath:      filepath.Join(baseDir, "charon-enr-private-key"),
			ValidatorKeysDir:    filepath.Join(baseDir, "validator_keys"),
			LockFilePath:        filepath.Join(baseDir, "cluster-lock.json"),
			PlaintextOutput:     true,
			BeaconNodeTimeout:   30 * time.Second,
		}

		vals, err := listActiveVals(ctx, config)
		require.NoError(t, err)
		require.Len(t, vals, len(lock.Validators))
	})

	t.Run("half validators in the cluster are active", func(t *testing.T) {
		validatorSet := beaconmock.ValidatorSet{}

		for idx, v := range lock.Validators {
			state := eth2v1.ValidatorStateActiveOngoing
			if idx%2 == 0 {
				state = eth2v1.ValidatorStateActiveExiting
			}
			validatorSet[eth2p0.ValidatorIndex(idx)] = &eth2v1.Validator{
				Index:   eth2p0.ValidatorIndex(idx),
				Balance: 42,
				Status:  state,
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

		baseDir := filepath.Join(root, fmt.Sprintf("op%d", 0))

		config := exitConfig{
			BeaconNodeEndpoints: []string{beaconMock.Address()},
			PrivateKeyPath:      filepath.Join(baseDir, "charon-enr-private-key"),
			ValidatorKeysDir:    filepath.Join(baseDir, "validator_keys"),
			LockFilePath:        filepath.Join(baseDir, "cluster-lock.json"),
			PlaintextOutput:     true,
			BeaconNodeTimeout:   30 * time.Second,
		}

		vals, err := listActiveVals(ctx, config)
		require.NoError(t, err)
		require.Len(t, vals, len(lock.Validators)/2)
	})
}

func TestExitListCLI(t *testing.T) {
	tests := []struct {
		name        string
		expectedErr string
		flags       []string
	}{
		{
			name:        "check flags",
			expectedErr: "load cluster lock: load cluster manifest from disk: load dag from disk: no file found",
			flags: []string{
				"--lock-file=test",
				"--beacon-node-endpoints=test1,test2",
				"--beacon-node-timeout=1ms",
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
			cmd := newExitCmd(newListActiveValidatorsCmd(runListActiveValidatorsCmd))
			cmd.SetArgs(append([]string{"active-validator-list"}, test.flags...))

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
