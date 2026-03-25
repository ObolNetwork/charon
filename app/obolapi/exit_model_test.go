// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi_test

import (
	"encoding/hex"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/testutil"
)

func TestPartialExitRequest(t *testing.T) {
	pr := obolapi.PartialExitRequest{
		UnsignedPartialExitRequest: obolapi.UnsignedPartialExitRequest{
			PartialExits: []obolapi.ExitBlob{
				{
					PublicKey:         string(testutil.RandomCorePubKey(t)),
					SignedExitMessage: *testutil.RandomExit(),
				},
			},
			ShareIdx: 0,
		},
		Signature: testutil.RandomSecp256k1Signature(),
	}

	htr, err := pr.HashTreeRoot()
	require.NoError(t, err)
	require.NotEmpty(t, htr)

	node, err := pr.GetTree()
	require.NoError(t, err)
	require.NotNil(t, node)

	jbytes, err := pr.MarshalJSON()
	require.NoError(t, err)

	var other obolapi.PartialExitRequest

	err = other.UnmarshalJSON(jbytes)
	require.NoError(t, err)
	require.Equal(t, other, pr)

	err = pr.HashTreeRootWith(ssz.DefaultHasherPool.Get())
	require.NoError(t, err)
	require.NotEmpty(t, htr)
}

func TestUnsignedPartialExitRequest(t *testing.T) {
	pr := obolapi.UnsignedPartialExitRequest{
		PartialExits: []obolapi.ExitBlob{
			{
				PublicKey:         string(testutil.RandomCorePubKey(t)),
				SignedExitMessage: *testutil.RandomExit(),
			},
		},
		ShareIdx: 0,
	}

	htr, err := pr.HashTreeRoot()
	require.NoError(t, err)
	require.NotEmpty(t, htr)

	node, err := pr.GetTree()
	require.NoError(t, err)
	require.NotNil(t, node)

	err = pr.HashTreeRootWith(ssz.DefaultHasherPool.Get())
	require.NoError(t, err)
	require.NotEmpty(t, htr)
}

func TestPartialExits(t *testing.T) {
	pr := obolapi.PartialExits{
		{
			PublicKey:         string(testutil.RandomCorePubKey(t)),
			SignedExitMessage: *testutil.RandomExit(),
		},
		{
			PublicKey:         string(testutil.RandomCorePubKey(t)),
			SignedExitMessage: *testutil.RandomExit(),
		},
	}

	htr, err := pr.HashTreeRoot()
	require.NoError(t, err)
	require.NotEmpty(t, htr)

	node, err := pr.GetTree()
	require.NoError(t, err)
	require.NotNil(t, node)

	err = pr.HashTreeRootWith(ssz.DefaultHasherPool.Get())
	require.NoError(t, err)
	require.NotEmpty(t, htr)
}

func TestFullExitAuthBlob(t *testing.T) {
	vp, err := testutil.RandomCorePubKey(t).Bytes()
	require.NoError(t, err)

	pr := obolapi.FullExitAuthBlob{
		LockHash:        testutil.RandomBytes32(),
		ValidatorPubkey: vp,
		ShareIndex:      0,
	}

	htr, err := pr.HashTreeRoot()
	require.NoError(t, err)
	require.NotEmpty(t, htr)

	node, err := pr.GetTree()
	require.NoError(t, err)
	require.NotNil(t, node)

	err = pr.HashTreeRootWith(ssz.DefaultHasherPool.Get())
	require.NoError(t, err)
	require.NotEmpty(t, htr)
}

func TestExitBlob(t *testing.T) {
	pr := obolapi.ExitBlob{
		PublicKey:         string(testutil.RandomCorePubKey(t)),
		SignedExitMessage: *testutil.RandomExit(),
	}

	htr, err := pr.HashTreeRoot()
	require.NoError(t, err)
	require.NotEmpty(t, htr)

	node, err := pr.GetTree()
	require.NoError(t, err)
	require.NotNil(t, node)

	err = pr.HashTreeRootWith(ssz.DefaultHasherPool.Get())
	require.NoError(t, err)
	require.NotEmpty(t, htr)
}

func TestExitBlobHashTreeRoot(t *testing.T) {
	zeroPubkey := "0x" + hex.EncodeToString(make([]byte, 48))

	nonZeroPubkey := make([]byte, 48)
	nonZeroPubkey[0] = 0xab
	nonZeroPubkeyHex := "0x" + hex.EncodeToString(nonZeroPubkey)

	nonZeroSig := eth2p0.BLSSignature{}
	nonZeroSig[0] = 0x01

	tests := []struct {
		name     string
		input    obolapi.ExitBlob
		expected string
	}{
		{
			name: "zeros",
			input: obolapi.ExitBlob{
				PublicKey: zeroPubkey,
				SignedExitMessage: eth2p0.SignedVoluntaryExit{
					Message:   &eth2p0.VoluntaryExit{},
					Signature: eth2p0.BLSSignature{},
				},
			},
			expected: "65595314b41aeacd2f0469c979f93cdff0aeb5cfa1c290d2a4084cbc9855de48",
		},
		{
			name: "epoch1_validator3",
			input: obolapi.ExitBlob{
				PublicKey: nonZeroPubkeyHex,
				SignedExitMessage: eth2p0.SignedVoluntaryExit{
					Message:   &eth2p0.VoluntaryExit{Epoch: 1, ValidatorIndex: 3},
					Signature: nonZeroSig,
				},
			},
			expected: "004ff00a261f09275d978c524ee23ad02629eb2fc94d16d3a3cab9035247d28c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.input.HashTreeRoot()
			require.NoError(t, err)
			require.Equal(t, tt.expected, hex.EncodeToString(got[:]))
		})
	}
}

func TestPartialExitsHashTreeRoot(t *testing.T) {
	zeroPubkey := "0x" + hex.EncodeToString(make([]byte, 48))

	nonZeroPubkey := make([]byte, 48)
	nonZeroPubkey[0] = 0xab
	nonZeroSig := eth2p0.BLSSignature{}
	nonZeroSig[0] = 0x01

	exitZero := obolapi.ExitBlob{
		PublicKey: zeroPubkey,
		SignedExitMessage: eth2p0.SignedVoluntaryExit{
			Message:   &eth2p0.VoluntaryExit{},
			Signature: eth2p0.BLSSignature{},
		},
	}
	exitNonZero := obolapi.ExitBlob{
		PublicKey: "0x" + hex.EncodeToString(nonZeroPubkey),
		SignedExitMessage: eth2p0.SignedVoluntaryExit{
			Message:   &eth2p0.VoluntaryExit{Epoch: 1, ValidatorIndex: 3},
			Signature: nonZeroSig,
		},
	}

	tests := []struct {
		name     string
		input    obolapi.PartialExits
		expected string
	}{
		{
			name:     "empty",
			input:    obolapi.PartialExits{},
			expected: "6080a24df6cb76f31cacdf4419ac9bf0ac092087f40ec93f10c4608f967ca23a",
		},
		{
			name:     "one_exit",
			input:    obolapi.PartialExits{exitZero},
			expected: "243b6b384bcf8dc6e72369247c6b0fa784c98077c15b402a9e4ea3335e479a12",
		},
		{
			name:     "two_exits",
			input:    obolapi.PartialExits{exitZero, exitNonZero},
			expected: "7e7ee8b65d37f3e5bdd859c150c8bc7f329c1c873cb2042636c6f25f730af037",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.input.HashTreeRoot()
			require.NoError(t, err)
			require.Equal(t, tt.expected, hex.EncodeToString(got[:]))
		})
	}
}

func TestUnsignedPartialExitRequestHashTreeRoot(t *testing.T) {
	zeroPubkey := "0x" + hex.EncodeToString(make([]byte, 48))

	nonZeroPubkey := make([]byte, 48)
	nonZeroPubkey[0] = 0xab
	nonZeroSig := eth2p0.BLSSignature{}
	nonZeroSig[0] = 0x01

	exitZero := obolapi.ExitBlob{
		PublicKey: zeroPubkey,
		SignedExitMessage: eth2p0.SignedVoluntaryExit{
			Message:   &eth2p0.VoluntaryExit{},
			Signature: eth2p0.BLSSignature{},
		},
	}
	exitNonZero := obolapi.ExitBlob{
		PublicKey: "0x" + hex.EncodeToString(nonZeroPubkey),
		SignedExitMessage: eth2p0.SignedVoluntaryExit{
			Message:   &eth2p0.VoluntaryExit{Epoch: 1, ValidatorIndex: 3},
			Signature: nonZeroSig,
		},
	}

	tests := []struct {
		name     string
		input    obolapi.UnsignedPartialExitRequest
		expected string
	}{
		{
			name:     "empty_share0",
			input:    obolapi.UnsignedPartialExitRequest{PartialExits: obolapi.PartialExits{}, ShareIdx: 0},
			expected: "b0dd7cbd107e45dbfa315f1d5da8ff11d50dcffbe38a4d2473583437ab18a408",
		},
		{
			name:     "one_exit_share2",
			input:    obolapi.UnsignedPartialExitRequest{PartialExits: obolapi.PartialExits{exitZero}, ShareIdx: 2},
			expected: "821eb5ff317540ae8e3e3c819b879a90bf42ad11be959f60c670f44f88cfa6a2",
		},
		{
			name:     "two_exits_share1",
			input:    obolapi.UnsignedPartialExitRequest{PartialExits: obolapi.PartialExits{exitZero, exitNonZero}, ShareIdx: 1},
			expected: "44a05ee801102e3b179cf2f70163fd2e2ede5bb53545336cf5912438b9e80125",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.input.HashTreeRoot()
			require.NoError(t, err)
			require.Equal(t, tt.expected, hex.EncodeToString(got[:]))
		})
	}
}

func TestFullExitAuthBlobHashTreeRoot(t *testing.T) {
	nonZeroLockHash := make([]byte, 32)
	nonZeroLockHash[0] = 0xde
	nonZeroLockHash[31] = 0xad

	nonZeroValidatorPubkey := make([]byte, 48)
	nonZeroValidatorPubkey[0] = 0x11

	tests := []struct {
		name     string
		input    obolapi.FullExitAuthBlob
		expected string
	}{
		{
			name: "zeros",
			input: obolapi.FullExitAuthBlob{
				LockHash:        make([]byte, 32),
				ValidatorPubkey: make([]byte, 48),
				ShareIndex:      0,
			},
			expected: "bad1ebffe915f474f39873c538915f5cb1b246dfc5dc98eed668aac9292f1351",
		},
		{
			name: "non_zero",
			input: obolapi.FullExitAuthBlob{
				LockHash:        nonZeroLockHash,
				ValidatorPubkey: nonZeroValidatorPubkey,
				ShareIndex:      7,
			},
			expected: "876b5e058873adfcd3cdadf87332d0fd2e21311e35df96b2c42529ae313b9a5b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.input.HashTreeRoot()
			require.NoError(t, err)
			require.Equal(t, tt.expected, hex.EncodeToString(got[:]))
		})
	}
}
