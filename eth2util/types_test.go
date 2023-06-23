// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2util_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/testutil"
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

func TestUnmarshallingSignedEpoch(t *testing.T) {
	sig := testutil.RandomBytes96()
	newTmpl := `{"epoch": 1,"signature": "%#x"}`
	b := []byte(fmt.Sprintf(newTmpl, sig))

	var e1 eth2util.SignedEpoch
	err := e1.UnmarshalJSON(b)
	testutil.RequireNoError(t, err)
	require.Equal(t, sig, e1.Signature[:])

	type legacySig [96]byte
	sigB, err := json.Marshal(legacySig(sig))
	require.NoError(t, err)
	oldTmpl := `{"epoch": 1,"signature": %s}`
	b = []byte(fmt.Sprintf(oldTmpl, sigB))

	var e2 eth2util.SignedEpoch
	err = e2.UnmarshalJSON(b)
	testutil.RequireNoError(t, err)
	require.Equal(t, sig, e2.Signature[:])
}
