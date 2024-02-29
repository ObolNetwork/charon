// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi_test

import (
	"testing"

	ssz "github.com/ferranbt/fastssz"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/testutil"
)

func Test_PartialExitRequest(t *testing.T) {
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
	require.EqualValues(t, other, pr)

	err = pr.HashTreeRootWith(ssz.DefaultHasherPool.Get())
	require.NoError(t, err)
	require.NotEmpty(t, htr)
}

func Test_UnsignedPartialExitRequest(t *testing.T) {
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

func Test_PartialExits(t *testing.T) {
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

func Test_FullExitAuthBlob(t *testing.T) {
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

func Test_ExitBlob(t *testing.T) {
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
