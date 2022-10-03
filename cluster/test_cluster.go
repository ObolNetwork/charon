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
	crand "crypto/rand"
	"io"
	"math/rand"
	"net"
	"testing"

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil"
)

// NewForT returns a new cluster lock with dv number of distributed validators, k threshold and n peers.
// It also returns the peer p2p keys and BLS secret shares. If the seed is zero a random cluster on available loopback
// ports is generated, else a deterministic cluster is generated.
// Note this is not defined in testutil since it is tightly coupled with the cluster package.
func NewForT(t *testing.T, dv, k, n, seed int, opts ...func(*Definition)) (Lock, []*ecdsa.PrivateKey, [][]*bls_sig.SecretKeyShare) {
	t.Helper()

	var (
		vals     []DistValidator
		p2pKeys  []*ecdsa.PrivateKey
		ops      []Operator
		dvShares [][]*bls_sig.SecretKeyShare
	)

	addrFunc := getAddrFunc(seed)

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
		p2pKey, err := ecdsa.GenerateKey(crypto.S256(), random)
		require.NoError(t, err)

		tcp := addrFunc(t) // localhost and lib-p2p tcp port
		udp := addrFunc(t) // localhost and discv5 udp port

		var r enr.Record
		r.Set(enr.IPv4(tcp.IP))
		r.Set(enr.TCP(tcp.Port))
		r.Set(enr.UDP(udp.Port))
		r.SetSeq(0)

		err = enode.SignV4(&r, p2pKey)
		require.NoError(t, err)

		enrStr, err := p2p.EncodeENR(r)
		require.NoError(t, err)

		addr := crypto.PubkeyToAddress(p2pKey.PublicKey)
		op := Operator{
			Address: addr.Hex(),
			ENR:     enrStr,
		}

		ops = append(ops, op)
		p2pKeys = append(p2pKeys, p2pKey)
	}

	def, err := NewDefinition("test cluster", dv, k,
		testutil.RandomETHAddress(), testutil.RandomETHAddress(),
		"0x00000000", ops, random)
	require.NoError(t, err)

	for _, opt := range opts {
		opt(&def)
	}
	confHash, err := hashDefinition(def, true)
	require.NoError(t, err)

	chainID, err := forkVersionToChainID(def.ForkVersion)
	require.NoError(t, err)

	for i := 0; i < n; i++ {
		def.Operators[i], err = signOperator(p2pKeys[i], def.Operators[i], confHash, chainID)
		require.NoError(t, err)
	}

	def, err = def.SetDefinitionHashes()
	require.NoError(t, err)

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

// getAddrFunc returns either actual available ports for zero seeds
// or deterministic addresses for non-zero seeds.
func getAddrFunc(seed int) func(*testing.T) *net.TCPAddr {
	if seed == 0 {
		return testutil.AvailableAddr
	}

	var j int

	return func(*testing.T) *net.TCPAddr {
		j++
		return &net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: j,
		}
	}
}
