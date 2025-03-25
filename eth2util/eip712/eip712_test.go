// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eip712_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/eip712"
)

func TestCreatorHash(t *testing.T) {
	// Obtained from legacy unit tests.
	data := eip712.TypedData{
		Domain: eip712.Domain{
			Name:    "Obol",
			Version: "1",
			ChainID: eth2util.Sepolia.ChainID,
		},
		Type: eip712.Type{
			Name: "CreatorConfigHash",
			Fields: []eip712.Field{
				{
					Name:  "creator_config_hash",
					Type:  eip712.PrimitiveString,
					Value: "0xe57f66637bdfa05cce6a78e8cf4120d67d305b485367a69baa5f738436533bcb",
				},
			},
		},
	}

	resp, err := eip712.HashTypedData(data)
	require.NoError(t, err)
	require.Equal(t, "7c8fe012e2f872ca7ec870164184f57b921166f80565ff74af7bee5796f973e4", hex.EncodeToString(resp))
}
