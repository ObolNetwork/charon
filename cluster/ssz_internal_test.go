// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster

import (
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	ssz "github.com/ferranbt/fastssz"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
)

func TestHashBuilderRegistration(t *testing.T) {
	const network = "goerli"
	clusterReg := RandomRegistration(t, network)

	var feeRecipient bellatrix.ExecutionAddress
	copy(feeRecipient[:], clusterReg.Message.FeeRecipient)

	pubkey, err := core.PubKeyFromBytes(clusterReg.Message.PubKey)
	require.NoError(t, err)

	eth2Pubkey, err := pubkey.ToETH2()
	require.NoError(t, err)

	eth2Reg := &eth2v1.SignedValidatorRegistration{
		Message: &eth2v1.ValidatorRegistration{
			FeeRecipient: feeRecipient,
			Timestamp:    clusterReg.Message.Timestamp,
			GasLimit:     uint64(clusterReg.Message.GasLimit),
			Pubkey:       eth2Pubkey,
		},
	}

	eth2hash, err := eth2Reg.Message.HashTreeRoot()
	require.NoError(t, err)

	hh := ssz.DefaultHasherPool.Get()
	defer ssz.DefaultHasherPool.Put(hh)

	require.NoError(t, hashRegistration(clusterReg.Message, hh))
	clusterRegHash, err := hh.HashRoot()
	require.NoError(t, err)
	require.Equal(t, eth2hash, clusterRegHash)
}
