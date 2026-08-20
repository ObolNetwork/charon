// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pk910/dynamic-ssz/hasher"
	"github.com/pk910/dynamic-ssz/treeproof"
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

	hh := hasher.DefaultHasherPool.Get()
	defer hasher.DefaultHasherPool.Put(hh)

	err = pr.HashTreeRootWith(hh)
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

	hh := hasher.DefaultHasherPool.Get()
	defer hasher.DefaultHasherPool.Put(hh)

	err = pr.HashTreeRootWith(hh)
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

	hh := hasher.DefaultHasherPool.Get()
	defer hasher.DefaultHasherPool.Put(hh)

	err = pr.HashTreeRootWith(hh)
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

	hh := hasher.DefaultHasherPool.Get()
	defer hasher.DefaultHasherPool.Put(hh)

	err = pr.HashTreeRootWith(hh)
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

	hh := hasher.DefaultHasherPool.Get()
	defer hasher.DefaultHasherPool.Put(hh)

	err = pr.HashTreeRootWith(hh)
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
		name  string
		input obolapi.ExitBlob
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
		},
	}

	roots := make(map[string]string)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.input.HashTreeRoot()
			require.NoError(t, err)

			roots[tt.name] = hex.EncodeToString(got[:])
		})
	}

	testutil.RequireGoldenJSON(t, roots)
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
		name  string
		input obolapi.PartialExits
	}{
		{
			name:  "empty",
			input: obolapi.PartialExits{},
		},
		{
			name:  "one_exit",
			input: obolapi.PartialExits{exitZero},
		},
		{
			name:  "two_exits",
			input: obolapi.PartialExits{exitZero, exitNonZero},
		},
	}

	roots := make(map[string]string)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.input.HashTreeRoot()
			require.NoError(t, err)

			roots[tt.name] = hex.EncodeToString(got[:])
		})
	}

	testutil.RequireGoldenJSON(t, roots)
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
		name  string
		input obolapi.UnsignedPartialExitRequest
	}{
		{
			name:  "empty_share0",
			input: obolapi.UnsignedPartialExitRequest{PartialExits: obolapi.PartialExits{}, ShareIdx: 0},
		},
		{
			name:  "one_exit_share2",
			input: obolapi.UnsignedPartialExitRequest{PartialExits: obolapi.PartialExits{exitZero}, ShareIdx: 2},
		},
		{
			name:  "two_exits_share1",
			input: obolapi.UnsignedPartialExitRequest{PartialExits: obolapi.PartialExits{exitZero, exitNonZero}, ShareIdx: 1},
		},
	}

	roots := make(map[string]string)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.input.HashTreeRoot()
			require.NoError(t, err)

			roots[tt.name] = hex.EncodeToString(got[:])
		})
	}

	testutil.RequireGoldenJSON(t, roots)
}

func TestFullExitAuthBlobHashTreeRoot(t *testing.T) {
	nonZeroLockHash := make([]byte, 32)
	nonZeroLockHash[0] = 0xde
	nonZeroLockHash[31] = 0xad

	nonZeroValidatorPubkey := make([]byte, 48)
	nonZeroValidatorPubkey[0] = 0x11

	tests := []struct {
		name  string
		input obolapi.FullExitAuthBlob
	}{
		{
			name: "zeros",
			input: obolapi.FullExitAuthBlob{
				LockHash:        make([]byte, 32),
				ValidatorPubkey: make([]byte, 48),
				ShareIndex:      0,
			},
		},
		{
			name: "non_zero",
			input: obolapi.FullExitAuthBlob{
				LockHash:        nonZeroLockHash,
				ValidatorPubkey: nonZeroValidatorPubkey,
				ShareIndex:      7,
			},
		},
	}

	roots := make(map[string]string)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.input.HashTreeRoot()
			require.NoError(t, err)

			roots[tt.name] = hex.EncodeToString(got[:])
		})
	}

	testutil.RequireGoldenJSON(t, roots)
}

// TestExitBlobProofTree ensures ExitBlob.GetTree exposes the interior of SignedExitMessage,
// so Merkle proofs can be generated for fields inside the signed exit. Inserting the
// precomputed SignedExitMessage root as an opaque leaf keeps the root identical but breaks
// these proofs, so this test fails on such an implementation.
func TestExitBlobProofTree(t *testing.T) {
	var sig eth2p0.BLSSignature
	for i := range sig {
		sig[i] = 0x11
	}

	pubkey := make([]byte, 48)
	for i := range pubkey {
		pubkey[i] = 0xab
	}

	e := obolapi.ExitBlob{
		PublicKey: "0x" + hex.EncodeToString(pubkey),
		SignedExitMessage: eth2p0.SignedVoluntaryExit{
			Message: &eth2p0.VoluntaryExit{
				Epoch:          42,
				ValidatorIndex: 7,
			},
			Signature: sig,
		},
	}

	root, err := e.HashTreeRoot()
	require.NoError(t, err)

	node, err := e.GetTree()
	require.NoError(t, err)
	require.Equal(t, root[:], node.Hash())

	msgRoot, err := e.SignedExitMessage.Message.HashTreeRoot()
	require.NoError(t, err)

	epochLeaf := make([]byte, 32)
	binary.LittleEndian.PutUint64(epochLeaf, uint64(e.SignedExitMessage.Message.Epoch))

	for name, target := range map[string][]byte{
		"voluntary_exit_root": msgRoot[:],
		"epoch_leaf":          epochLeaf,
	} {
		t.Run(name, func(t *testing.T) {
			gindex, ok := findGeneralizedIndex(node, target, 1, 8)
			require.True(t, ok, "target node not present in proof tree: SignedExitMessage is an opaque leaf")

			proof, err := node.Prove(gindex)
			require.NoError(t, err)
			require.Equal(t, target, proof.Leaf)

			valid, err := treeproof.VerifyProof(root[:], proof)
			require.NoError(t, err)
			require.True(t, valid)
		})
	}
}

// findGeneralizedIndex walks the proof tree up to maxDepth levels and returns the generalized
// index of the first node whose hash equals target.
func findGeneralizedIndex(n *treeproof.Node, target []byte, gindex, maxDepth int) (int, bool) {
	if n == nil || maxDepth < 0 {
		return 0, false
	}

	if bytes.Equal(n.Hash(), target) {
		return gindex, true
	}

	if idx, ok := findGeneralizedIndex(n.Left(), target, gindex*2, maxDepth-1); ok {
		return idx, ok
	}

	return findGeneralizedIndex(n.Right(), target, gindex*2+1, maxDepth-1)
}
