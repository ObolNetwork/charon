// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff_test

import (
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/core/hotstuff"
)

func TestSignVerify(t *testing.T) {
	privKey, err := k1.GeneratePrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()
	require.NotNil(t, pubKey)

	valueHash, err := hotstuff.HashValue([]byte("value"))
	require.NoError(t, err)

	sig, err := hotstuff.Sign(privKey, hotstuff.MsgCommit, 3, valueHash)
	require.NoError(t, err)

	hash, err := hotstuff.HashMsg(hotstuff.MsgCommit, 3, valueHash)
	require.NoError(t, err)

	pk, err := k1util.Recover(hash[:], sig)
	require.NoError(t, err)
	require.Equal(t, pubKey.SerializeCompressed(), pk.SerializeCompressed())
}
