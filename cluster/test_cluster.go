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
	crand "crypto/rand"
	"io"
	"math/rand"
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/enr"
	tblsv2 "github.com/obolnetwork/charon/tbls/v2"
	"github.com/obolnetwork/charon/testutil"
)

// NewForT returns a new cluster lock with dv number of distributed validators, k threshold and n peers.
// It also returns the peer p2p keys and BLS secret shares. If the seed is zero a random cluster on available loopback
// ports is generated, else a deterministic cluster is generated.
// Note this is not defined in testutil since it is tightly coupled with the cluster package.
func NewForT(t *testing.T, dv, k, n, seed int, opts ...func(*Definition)) (Lock, []*k1.PrivateKey, [][]tblsv2.PrivateKey) {
	t.Helper()

	var (
		vals     []DistValidator
		p2pKeys  []*k1.PrivateKey
		ops      []Operator
		dvShares [][]tblsv2.PrivateKey
	)

	random := io.Reader(rand.New(rand.NewSource(int64(seed)))) //nolint:gosec // Explicit use of weak random generator for determinism.
	if seed == 0 {
		random = crand.Reader
	} else {
		rand.Seed(int64(seed))
	}

	for i := 0; i < dv; i++ {
		rootSecret, err := tblsv2.GenerateSecretKey()
		require.NoError(t, err)

		rootPublic, err := tblsv2.SecretToPublicKey(rootSecret)
		require.NoError(t, err)

		shares, err := tblsv2.ThresholdSplit(rootSecret, uint(n), uint(k))
		require.NoError(t, err)

		var pubshares [][]byte
		var privshares []tblsv2.PrivateKey
		for i := 0; i < n; i++ {
			sharePrivkey := shares[i+1] // Share indexes are 1-indexed.

			sharePub, err := tblsv2.SecretToPublicKey(sharePrivkey)
			require.NoError(t, err)

			pubshares = append(pubshares, sharePub[:])

			privshares = append(privshares, sharePrivkey)
		}

		vals = append(vals, DistValidator{
			PubKey:    rootPublic[:],
			PubShares: pubshares,
		})
		dvShares = append(dvShares, privshares)
	}

	for i := 0; i < n; i++ {
		// Generate ENR
		p2pKey := testutil.GenerateInsecureK1Key(t, random)

		record, err := enr.New(p2pKey)
		require.NoError(t, err)

		addr := eth2util.PublicKeyToAddress(p2pKey.PubKey())
		op := Operator{
			Address: addr,
			ENR:     record.String(),
			// Set to empty signatures instead of nil so aligned with unmarshalled json
			ENRSignature:    ethHex{},
			ConfigSignature: ethHex{},
		}

		ops = append(ops, op)
		p2pKeys = append(p2pKeys, p2pKey)
	}

	// Use operator 0 as the creator.
	creator := Creator{Address: ops[0].Address}

	def, err := NewDefinition("test cluster", dv, k,
		testutil.RandomETHAddress(), testutil.RandomETHAddress(),
		"0x00000000", creator, ops, random, opts...)
	require.NoError(t, err)

	// Definition version prior to v1.3.0 don't support EIP712 signatures.
	if supportEIP712Sigs(def.Version) {
		for i := 0; i < n; i++ {
			def.Operators[i], err = signOperator(p2pKeys[i], def, def.Operators[i])
			require.NoError(t, err)
		}

		def, err = signCreator(p2pKeys[0], def)
		require.NoError(t, err)

		// Recalculate definition hash after adding signatures.
		def, err = def.SetDefinitionHashes()
		require.NoError(t, err)
	}

	lock := Lock{
		Definition:         def,
		Validators:         vals,
		SignatureAggregate: nil,
	}

	lock, err = lock.SetLockHash()
	require.NoError(t, err)

	lock.SignatureAggregate, err = aggSign(dvShares, lock.LockHash)
	require.NoError(t, err)

	return lock, p2pKeys, dvShares
}
