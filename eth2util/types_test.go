// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2util_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
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
	epoch := eth2p0.Epoch(rand.Int())
	sig := testutil.RandomBytes96()

	newTmpl := `{"epoch": %d,"signature": "%#x"}`
	b := []byte(fmt.Sprintf(newTmpl, epoch, sig))

	var e1 eth2util.SignedEpoch
	err := e1.UnmarshalJSON(b)
	testutil.RequireNoError(t, err)
	require.Equal(t, sig, e1.Signature[:])
	require.Equal(t, epoch, e1.Epoch)

	type legacySig [96]byte
	sigB, err := json.Marshal(legacySig(sig))
	require.NoError(t, err)
	oldTmpl := `{"epoch": %d,"signature": %s}`
	b = []byte(fmt.Sprintf(oldTmpl, epoch, sigB))

	var e2 eth2util.SignedEpoch
	err = e2.UnmarshalJSON(b)
	testutil.RequireNoError(t, err)
	require.Equal(t, sig, e2.Signature[:])
	require.Equal(t, epoch, e2.Epoch)
}
