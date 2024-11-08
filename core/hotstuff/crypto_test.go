// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core/hotstuff"
	"github.com/obolnetwork/charon/tbls"
)

func TestSignVerify(t *testing.T) {
	privKey, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubKey, err := tbls.SecretToPublicKey(privKey)
	require.NoError(t, err)

	sig, err := hotstuff.Sign(privKey, hotstuff.MsgCommit, 3, "value")
	require.NoError(t, err)

	err = hotstuff.Verify(pubKey, hotstuff.MsgCommit, 3, "value", sig)
	require.NoError(t, err)
}
