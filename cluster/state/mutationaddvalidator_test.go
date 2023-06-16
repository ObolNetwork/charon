// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/state"
	statepb "github.com/obolnetwork/charon/cluster/statepb/v1"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -update

func TestGenValidators(t *testing.T) {
	setIncrementingTime(t)

	b, err := os.ReadFile("testdata/lock.json")
	require.NoError(t, err)
	var lock cluster.Lock
	require.NoError(t, json.Unmarshal(b, &lock))

	// Convert validators into state.Validator
	var vals []*statepb.Validator
	for i, validator := range lock.Validators {
		val, err := state.ValidatorToProto(validator, lock.ValidatorAddresses[i])
		require.NoError(t, err)

		vals = append(vals, val)
	}

	parent, err := hex.DecodeString("605ec6de4f1ae997dd3545513b934c335a833f4635dc9fad7758314f79ff0fae")
	require.NoError(t, err)
	signed, err := state.NewGenValidators(parent, vals)
	require.NoError(t, err)

	t.Run("unmarshal", func(t *testing.T) {
		b, err := json.Marshal(signed)
		require.NoError(t, err)
		var signed2 *statepb.SignedMutation
		require.NoError(t, json.Unmarshal(b, &signed2))

		testutil.RequireProtoEqual(t, signed, signed2)
	})

	t.Run("transform", func(t *testing.T) {
		cluster, err := state.Transform(new(statepb.Cluster), signed)
		require.NoError(t, err)

		testutil.RequireProtosEqual(t, vals, cluster.Validators)
	})

	t.Run("proto", func(t *testing.T) {
		testutil.RequireGoldenProto(t, signed)
	})
}

//go:generate go test . -update -run=TestAddValidators && go test . -run=TestAddValidators

func TestAddValidators(t *testing.T) {
	setIncrementingTime(t)

	nodes := 4
	lock, secrets, _ := cluster.NewForT(t, 3, 3, nodes, 1)

	// Convert validators into state.Validator
	var vals []*statepb.Validator
	for i, validator := range lock.Validators {
		val, err := state.ValidatorToProto(validator, lock.ValidatorAddresses[i])
		require.NoError(t, err)

		vals = append(vals, val)
	}

	genVals, err := state.NewGenValidators(testutil.RandomBytes32(), vals)
	require.NoError(t, err)
	genHash, err := state.Hash(genVals)
	testutil.RequireNoError(t, err)

	var approvals []*statepb.SignedMutation
	for _, secret := range secrets {
		approval, err := state.SignNodeApproval(genHash, secret)
		require.NoError(t, err)

		approvals = append(approvals, approval)
	}

	nodeApprovals, err := state.NewNodeApprovalsComposite(approvals)
	require.NoError(t, err)

	addVals, err := state.NewAddValidators(genVals, nodeApprovals)
	require.NoError(t, err)

	t.Run("proto", func(t *testing.T) {
		testutil.RequireGoldenProto(t, addVals)
	})

	t.Run("unmarshal", func(t *testing.T) {
		b, err := proto.Marshal(addVals)
		require.NoError(t, err)

		addVals2 := new(statepb.SignedMutation)
		require.NoError(t, proto.Unmarshal(b, addVals2))

		testutil.RequireProtoEqual(t, addVals, addVals2)
	})

	t.Run("transform", func(t *testing.T) {
		cluster, err := state.NewClusterFromLock(lock)
		require.NoError(t, err)

		cluster.Validators = nil

		cluster, err = state.Transform(cluster, addVals)
		require.NoError(t, err)

		testutil.RequireProtosEqual(t, vals, cluster.Validators)
	})
}
