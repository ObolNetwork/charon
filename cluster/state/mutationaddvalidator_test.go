// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/state"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -update

func TestGenValidators(t *testing.T) {
	setIncrementingTime(t)

	b, err := os.ReadFile("testdata/lock2.json")
	require.NoError(t, err)
	var lock cluster.Lock
	require.NoError(t, json.Unmarshal(b, &lock))

	// Convert validators into state.Validator
	var vals []state.Validator
	for i, validator := range lock.Validators {
		vals = append(vals, state.Validator{
			PubKey:              validator.PubKey,
			PubShares:           validator.PubShares,
			FeeRecipientAddress: lock.ValidatorAddresses[i].FeeRecipientAddress,
			WithdrawalAddress:   lock.ValidatorAddresses[i].WithdrawalAddress,
		})
	}

	parent, err := hex.DecodeString("605ec6de4f1ae997dd3545513b934c335a833f4635dc9fad7758314f79ff0fae")
	require.NoError(t, err)
	signed, err := state.NewGenValidators([32]byte(parent), vals)
	require.NoError(t, err)

	t.Run("unmarshal", func(t *testing.T) {
		b, err := json.Marshal(signed)
		require.NoError(t, err)
		var signed2 state.SignedMutation
		require.NoError(t, json.Unmarshal(b, &signed2))

		require.Equal(t, signed, signed2)
	})

	t.Run("transform", func(t *testing.T) {
		cluster, err := signed.Transform(state.Cluster{})
		require.NoError(t, err)

		require.Equal(t, vals, cluster.Validators)
	})

	t.Run("json", func(t *testing.T) {
		testutil.RequireGoldenJSON(t, signed)
	})
}

func TestAddValidators(t *testing.T) {
	setIncrementingTime(t)

	nodes := 4
	lock, secrets, _ := cluster.NewForT(t, 3, 3, nodes, 1)

	// Convert validators into state.Validator
	var vals []state.Validator
	for i, validator := range lock.Validators {
		vals = append(vals, state.Validator{
			PubKey:              validator.PubKey,
			PubShares:           randomShares(t, nodes),
			FeeRecipientAddress: lock.ValidatorAddresses[i].FeeRecipientAddress,
			WithdrawalAddress:   lock.ValidatorAddresses[i].WithdrawalAddress,
		})
	}

	genVals, err := state.NewGenValidators(testutil.RandomArray32(), vals)
	require.NoError(t, err)
	genHash, err := genVals.Hash()
	testutil.RequireNoError(t, err)

	var approvals []state.SignedMutation
	for _, secret := range secrets {
		approval, err := state.SignNodeApproval(genHash, secret)
		require.NoError(t, err)

		approvals = append(approvals, approval)
	}

	nodeApprovals, err := state.NewNodeApprovalsComposite(approvals)
	require.NoError(t, err)

	addVals, err := state.NewAddValidators(genVals, nodeApprovals)
	require.NoError(t, err)

	t.Run("json", func(t *testing.T) {
		testutil.RequireGoldenJSON(t, addVals)
	})

	t.Run("unmarshal", func(t *testing.T) {
		b, err := json.MarshalIndent(addVals, "", "  ")
		require.NoError(t, err)
		t.Logf("%s", b)
		var addVals2 state.SignedMutation
		require.NoError(t, json.Unmarshal(b, &addVals2))

		require.Equal(t, addVals, addVals2)
	})

	t.Run("transform", func(t *testing.T) {
		cluster, err := state.NewClusterFromLock(lock)
		require.NoError(t, err)

		cluster.Validators = nil

		cluster, err = addVals.Transform(cluster)
		require.NoError(t, err)

		require.Equal(t, vals, cluster.Validators)
	})
}

func randomShares(t *testing.T, n int) [][]byte {
	t.Helper()

	var resp [][]byte
	for i := 0; i < n; i++ {
		pubkey := testutil.RandomEth2PubKey(t)
		resp = append(resp, pubkey[:])
	}

	return resp
}
