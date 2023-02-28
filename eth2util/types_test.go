// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2util_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util"
)

func TestEpochHashRoot(t *testing.T) {
	epoch := eth2util.SignedEpoch{Epoch: 2}

	resp, err := epoch.HashTreeRoot()
	require.NoError(t, err)
	require.Equal(t,
		"0200000000000000000000000000000000000000000000000000000000000000",
		hex.EncodeToString(resp[:]),
	)
}
