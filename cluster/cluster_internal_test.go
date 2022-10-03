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
	secret0, op0 := randomOperator(t)
	secret1, op1 := randomOperator(t)

	definition, err := NewDefinition("test definition", 1, 2,
		"", "", eth2util.Sepolia.ForkVersion, []Operator{op0, op1},
		rand.New(rand.NewSource(1)))
	require.NoError(t, err)

	configHash, err := hashDefinition(definition, true)
	require.NoError(t, err)

	definition.Operators[0], err = signOperator(secret0, op0, configHash, eth2util.Sepolia.ChainID)
	require.NoError(t, err)

	definition.Operators[1], err = signOperator(secret1, op1, configHash, eth2util.Sepolia.ChainID)
	require.NoError(t, err)

	err = definition.VerifySignatures()
	require.NoError(t, err)
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
