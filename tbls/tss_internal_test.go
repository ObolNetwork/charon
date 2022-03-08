// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tbls

import (
	"crypto/rand"
	"testing"

	"github.com/dB2510/kryptology/pkg/signatures/bls/bls_sig"
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

			shares, verifiers, err := generateSecretShares(*secret, 3, 5, rand.Reader)
			require.NoError(t, err)
			require.NotNil(t, shares)
			require.NotNil(t, verifiers)
		})
	}
}
