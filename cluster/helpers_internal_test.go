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

package cluster

import (
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil"
)

func TestVerifySig(t *testing.T) {
	secret, err := crypto.GenerateKey()
	require.NoError(t, err)

	addr := crypto.PubkeyToAddress(secret.PublicKey)
	digest := testutil.RandomRoot()
	sig, err := crypto.Sign(digest[:], secret)
	require.NoError(t, err)

	t.Run("valid signature", func(t *testing.T) {
		ok, err := verifySig(addr.String(), digest[:], sig)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("invalid signature length", func(t *testing.T) {
		var invalidSig [70]byte
		ok, err := verifySig(addr.String(), digest[:], invalidSig[:])
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid signature length")
		require.False(t, ok)
	})

	t.Run("invalid recovery id", func(t *testing.T) {
		sig[k1RecIdx] = byte(165) // Make the last byte invalid.
		ok, err := verifySig(addr.String(), digest[:], sig)
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid recovery id")
		require.False(t, ok)
	})
}
