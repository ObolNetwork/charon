// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package tbls

import (
	"crypto/rand"
	"testing"

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/stretchr/testify/require"
)

func TestGenerateSecretShares(t *testing.T) {
	for i := 0; i < 10; i++ {
		t.Run("GenerateSecretShares", func(t *testing.T) {
			ikm := make([]byte, 32)
			cnt, err := rand.Read(ikm)
			require.NoError(t, err)
			require.Equal(t, 32, cnt)

			secret, err := new(bls_sig.SecretKey).Generate(ikm)
			require.NoError(t, err)
			require.NotNil(t, secret)

			shares, verifiers, err := SplitSecret(secret, 3, 5, rand.Reader)
			require.NoError(t, err)
			require.NotNil(t, shares)
			require.NotNil(t, verifiers)
		})
	}
}
