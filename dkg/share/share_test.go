// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package share_test

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/dkg/share"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil"
)

func TestMsgFromShare_Empty(t *testing.T) {
	s := share.Share{}
	msg := share.MsgFromShare(s)

	requireAllZero(t, msg.PubKey)
	requireAllZero(t, msg.SecretShare)
	require.Empty(t, msg.PubShares)
}

func TestMsgFromShare_Filled(t *testing.T) {
	pubKey := tbls.PublicKey{1, 2, 3, 4}
	secretShare := tbls.PrivateKey{5, 6, 7, 8}
	publicShares := map[int]tbls.PublicKey{
		2: tbls.PublicKey(testutil.RandomEth2PubKey(t)),
		1: tbls.PublicKey(testutil.RandomEth2PubKey(t)),
	}

	s := share.Share{
		PubKey:       pubKey,
		SecretShare:  secretShare,
		PublicShares: publicShares,
	}

	msg := share.MsgFromShare(s)

	require.Equal(t, msg.PubKey, pubKey[:])
	require.Equal(t, msg.SecretShare, secretShare[:])
	require.Len(t, msg.PubShares, 2)
	require.EqualValues(t, msg.PubShares[0], publicShares[1])
}

func requireAllZero(t *testing.T, b []byte) {
	t.Helper()

	c := slices.ContainsFunc(b, func(v byte) bool { return v != 0 })
	require.False(t, c, "byte slice contains non-zero value")
}
