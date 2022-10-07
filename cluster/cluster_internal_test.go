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
	"crypto/ecdsa"
	"fmt"
	"math/rand"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/testutil"
)

func TestDefinitionVerify(t *testing.T) {
	var err error

	secret0, op0 := randomOperator(t)
	secret1, op1 := randomOperator(t)

	t.Run("verify definition v1.3", func(t *testing.T) {
		definition := randomDefinition(t, op0, op1)

		definition.Operators[0], err = signOperator(secret0, definition, op0)
		require.NoError(t, err)

		definition.Operators[1], err = signOperator(secret1, definition, op1)
		require.NoError(t, err)

		err = definition.VerifySignatures()
		require.NoError(t, err)
	})

	t.Run("verify definition v1.2 or lower", func(t *testing.T) {
		def := randomDefinition(t, op0, op1)
		def.Version = v1_2
		require.NoError(t, def.VerifySignatures())
		def.Version = v1_0
		require.NoError(t, def.VerifySignatures())
	})

	t.Run("unsigned operators", func(t *testing.T) {
		def := randomDefinition(t, op0, op1)
		def.Operators = []Operator{{}, {}}

		require.NoError(t, def.VerifySignatures())
	})

	t.Run("empty operator signatures", func(t *testing.T) {
		def := randomDefinition(t, op0, op1)

		// Empty ENR sig
		err := def.VerifySignatures()
		require.Error(t, err)
		require.ErrorContains(t, err, "empty operator enr signature")

		// Empty Config sig
		def.Operators[0].ENRSignature = []byte{1, 2, 3}
		err = def.VerifySignatures()
		require.Error(t, err)
		require.ErrorContains(t, err, "empty operator config signature")
	})

	t.Run("some operators didn't sign", func(t *testing.T) {
		definition := randomDefinition(t, op0, op1)
		definition.Operators[0] = Operator{} // Operator with no address, enr sig or config sig

		// Only operator 1 signed.
		definition.Operators[1], err = signOperator(secret1, definition, op1)
		require.NoError(t, err)

		err = definition.VerifySignatures()
		require.Error(t, err)
		require.ErrorContains(t, err, "some operators signed while others didn't")
	})
}

// randomOperator returns a random ETH1 private key and populated operator struct (excluding config signature).
func randomOperator(t *testing.T) (*ecdsa.PrivateKey, Operator) {
	t.Helper()

	secret, err := crypto.GenerateKey()
	require.NoError(t, err)

	addr := crypto.PubkeyToAddress(secret.PublicKey)

	return secret, Operator{
		Address: addr.Hex(),
		ENR:     fmt.Sprintf("enr://%x", testutil.RandomBytes32()),
	}
}

// randomDefinition returns a test cluster definition with version set to v1.3.0.
func randomDefinition(t *testing.T, op0, op1 Operator) Definition {
	t.Helper()

	definition, err := NewDefinition("test definition", 1, 2,
		"", "", eth2util.Sepolia.ForkVersionHex, []Operator{op0, op1},
		rand.New(rand.NewSource(1)))
	require.NoError(t, err)

	// TODO(xenowits): Remove the line below when v1.3 is the current version.
	definition.Version = v1_3

	resp, err := definition.SetDefinitionHashes()
	require.NoError(t, err)

	return resp
}

func TestSupportEIP712Sigs(t *testing.T) {
	var (
		unsupported = v1_2
		supported   = v1_3
	)
	require.False(t, supportEIP712Sigs(unsupported))
	require.True(t, supportEIP712Sigs(supported))
}
