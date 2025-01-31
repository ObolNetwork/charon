// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2util_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"

	eth2spec "github.com/attestantio/go-eth2-client/spec"
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

	newTmpl := `{"epoch":"%d","signature":"%#x"}`
	b := []byte(fmt.Sprintf(newTmpl, epoch, sig))

	var e1 eth2util.SignedEpoch
	err := e1.UnmarshalJSON(b)
	testutil.RequireNoError(t, err)
	require.Equal(t, sig, e1.Signature[:])
	require.Equal(t, epoch, e1.Epoch)

	b2, err := json.Marshal(eth2util.SignedEpoch{
		Epoch:     epoch,
		Signature: eth2p0.BLSSignature(sig),
	})
	testutil.RequireNoError(t, err)
	require.Equal(t, string(b), string(b2))

	var e2 eth2util.SignedEpoch
	err = e2.UnmarshalJSON(b)
	testutil.RequireNoError(t, err)
	require.Equal(t, sig, e2.Signature[:])
	require.Equal(t, epoch, e2.Epoch)
}

func TestToETH2(t *testing.T) {
	tests := []struct {
		version         eth2util.DataVersion
		expectedVersion eth2spec.DataVersion
	}{
		{
			version:         eth2util.DataVersionUnknown,
			expectedVersion: eth2spec.DataVersionUnknown,
		},
		{
			version:         eth2util.DataVersionPhase0,
			expectedVersion: eth2spec.DataVersionPhase0,
		},
		{
			version:         eth2util.DataVersionAltair,
			expectedVersion: eth2spec.DataVersionAltair,
		},
		{
			version:         eth2util.DataVersionBellatrix,
			expectedVersion: eth2spec.DataVersionBellatrix,
		},
		{
			version:         eth2util.DataVersionCapella,
			expectedVersion: eth2spec.DataVersionCapella,
		},
		{
			version:         eth2util.DataVersionDeneb,
			expectedVersion: eth2spec.DataVersionDeneb,
		},
		{
			version:         eth2util.DataVersionElectra,
			expectedVersion: eth2spec.DataVersionElectra,
		},
	}
	for _, test := range tests {
		t.Run(test.version.String(), func(t *testing.T) {
			require.Equal(t, test.expectedVersion, test.version.ToETH2())
		},
		)
	}
}

func TestDataVersionFromETH2(t *testing.T) {
	tests := []struct {
		version         eth2spec.DataVersion
		expectedVersion eth2util.DataVersion
		expectedErr     string
	}{
		{
			version:         eth2spec.DataVersionUnknown,
			expectedVersion: eth2util.DataVersionUnknown,
			expectedErr:     "unknown data version",
		},
		{
			version:         eth2spec.DataVersionPhase0,
			expectedVersion: eth2util.DataVersionPhase0,
		},
		{
			version:         eth2spec.DataVersionAltair,
			expectedVersion: eth2util.DataVersionAltair,
		},
		{
			version:         eth2spec.DataVersionBellatrix,
			expectedVersion: eth2util.DataVersionBellatrix,
		},
		{
			version:         eth2spec.DataVersionCapella,
			expectedVersion: eth2util.DataVersionCapella,
		},
		{
			version:         eth2spec.DataVersionDeneb,
			expectedVersion: eth2util.DataVersionDeneb,
		},
		{
			version:         eth2spec.DataVersionElectra,
			expectedVersion: eth2util.DataVersionElectra,
		},
	}
	for _, test := range tests {
		t.Run(test.expectedVersion.String(), func(t *testing.T) {
			actual, err := eth2util.DataVersionFromETH2(test.version)
			if test.expectedErr != "" {
				require.ErrorContains(t, err, test.expectedErr)
			}
			require.Equal(t, test.expectedVersion, actual)
		},
		)
	}
}
