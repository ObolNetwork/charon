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

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil"
)

// NewForT returns a new cluster lock with dv number of distributed validators, k threshold and n peers.
// It also returns the peer p2p keys and BLS secret shares. If the seed is zero a random cluster on available loopback
// ports is generated, else a deterministic cluster is generated.
// Note this is not defined in testutil since it is tightly coupled with the cluster package.
func NewForT(t *testing.T, dv, k, n, seed int, opts ...func(*Definition)) (Lock, []*k1.PrivateKey, [][]*bls_sig.SecretKeyShare) {
	t.Helper()

	var (
		vals     []DistValidator
		p2pKeys  []*k1.PrivateKey
		ops      []Operator
		dvShares [][]*bls_sig.SecretKeyShare
	)

	random := io.Reader(rand.New(rand.NewSource(int64(seed)))) //nolint:gosec // Explicit use of weak random generator for determinism.
	if seed == 0 {
		random = crand.Reader
	} else {
		rand.Seed(int64(seed))
	}

	for i := 0; i < dv; i++ {
		tss, shares, err := tbls.GenerateTSS(k, n, random)
		require.NoError(t, err)

		pk, err := tss.PublicKey().MarshalBinary()
		require.NoError(t, err)

		var pubshares [][]byte
		for i := 0; i < n; i++ {
			share := tss.PublicShare(i + 1) // Share indexes are 1-indexed.

			b, err := share.MarshalBinary()
			require.NoError(t, err)

			pubshares = append(pubshares, b)
		}

		vals = append(vals, DistValidator{
			PubKey:    pk,
			PubShares: pubshares,
		})
		dvShares = append(dvShares, shares)
	}

	for i := 0; i < n; i++ {
		// Generate ENR
		p2pKey := testutil.GenerateInsecureK1Key(t, random)

		record, err := enr.New(p2pKey)
		require.NoError(t, err)

		pk := p2pKey.PubKey().ToECDSA()
		addr := crypto.PubkeyToAddress(*pk)
		op := Operator{
			Address: addr.Hex(),
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
