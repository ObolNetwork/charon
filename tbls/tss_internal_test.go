// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

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
