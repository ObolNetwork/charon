// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"path/filepath"
	"testing"

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

	for opIdx := 0; opIdx < operatorAmt; opIdx++ {
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
		BeaconNodeURL:    beaconMock.Address(),
		PrivateKeyPath:   filepath.Join(baseDir, "charon-enr-private-key"),
		ValidatorKeysDir: filepath.Join(baseDir, "validator_keys"),
		LockFilePath:     filepath.Join(baseDir, "cluster-lock.json"),
		PlaintextOutput:  true,
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

	for opIdx := 0; opIdx < operatorAmt; opIdx++ {
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
			BeaconNodeURL:    beaconMock.Address(),
			PrivateKeyPath:   filepath.Join(baseDir, "charon-enr-private-key"),
			ValidatorKeysDir: filepath.Join(baseDir, "validator_keys"),
			LockFilePath:     filepath.Join(baseDir, "cluster-lock.json"),
			PlaintextOutput:  true,
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
			BeaconNodeURL:    beaconMock.Address(),
			PrivateKeyPath:   filepath.Join(baseDir, "charon-enr-private-key"),
			ValidatorKeysDir: filepath.Join(baseDir, "validator_keys"),
			LockFilePath:     filepath.Join(baseDir, "cluster-lock.json"),
			PlaintextOutput:  true,
		}

		vals, err := listActiveVals(ctx, config)
		require.NoError(t, err)
		require.Len(t, vals, len(lock.Validators)/2)
	})
}
