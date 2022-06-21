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

	"github.com/obolnetwork/charon/testutil"
)

func TestENRSignature(t *testing.T) {
	_, op := randomOperator(t)
	require.NoError(t, op.VerifySignature())
}

func TestDefinitionSealed(t *testing.T) {
	secret1, op1 := randomOperator(t)
	secret2, op2 := randomOperator(t)

	definition := NewDefinition("test definition", 1, 2,
		"", "", "", []Operator{op1, op2},
		rand.New(rand.NewSource(1)))

	configHash, err := ConfigHash(definition)
	require.NoError(t, err)

	definition.Operators[0].ConfigSignature = configSignature(t, secret1, op1.Address, configHash)
	definition.Operators[1].ConfigSignature = configSignature(t, secret2, op2.Address, configHash)

	sealed, err := definition.Sealed()
	require.NoError(t, err)
	require.True(t, sealed)
}

// configSignature signs the config hash digest and returns the signature.
func configSignature(t *testing.T, secret *ecdsa.PrivateKey, addr string, configHash [32]byte) []byte {
	t.Helper()

	nonce := 0
	digest, err := digestEIP712(addr, configHash[:], nonce)
	require.NoError(t, err)

	sig, err := crypto.Sign(digest[:], secret)
	require.NoError(t, err)

	return sig
}

// randomOperator returns a random ETH1 private key and populated operator struct (excluding config signature).
func randomOperator(t *testing.T) (*ecdsa.PrivateKey, Operator) {
	t.Helper()

	secret, err := crypto.GenerateKey()
	require.NoError(t, err)

	enr := fmt.Sprintf("enr://%x", testutil.RandomBytes32())
	nonce := 0
	addr := fmt.Sprintf("%#x", crypto.PubkeyToAddress(secret.PublicKey))
	digest, err := digestEIP712(addr, []byte(enr), nonce)
	require.NoError(t, err)
	sig, err := crypto.Sign(digest[:], secret)
	require.NoError(t, err)

	return secret, Operator{
		Address:      addr,
		ENR:          enr,
		Nonce:        nonce,
		ENRSignature: sig,
	}
}
