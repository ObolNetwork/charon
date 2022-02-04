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

package cluster

import (
	"crypto/ecdsa"
	"crypto/rand"
	"net"
	"testing"

	"github.com/drand/kyber"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/crypto"
)

// NewForT returns a new random cluster manifest with threshold m and size n.
// It also returns the peer p2p keys and BLS keyshards.
// Note that the threshold signatures are stubs at this point.
func NewForT(t *testing.T, m, n int) (Manifest, []*ecdsa.PrivateKey, []kyber.Scalar) {
	t.Helper()

	var (
		members []crypto.BLSPubkeyHex
		enrs    []string
		p2pKeys []*ecdsa.PrivateKey
		blsKeys []kyber.Scalar
	)
	for i := 0; i < n; i++ {
		{
			// Generate fake BLS shards.
			privkey, pubkey := crypto.NewKeyPair()
			members = append(members, crypto.BLSPubkeyHex{Point: pubkey})
			blsKeys = append(blsKeys, privkey)
		}
		{
			// Generate ENR
			p2pKey, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
			require.NoError(t, err)

			addr := availableLocalAddr(t)

			var r enr.Record
			r.Set(enr.IPv4(addr.IP))
			r.Set(enr.TCP(addr.Port))
			r.SetSeq(1)

			err = enode.SignV4(&r, p2pKey)
			require.NoError(t, err)

			res, err := EncodeENR(r)
			require.NoError(t, err)

			enrs = append(enrs, res)
			p2pKeys = append(p2pKeys, p2pKey)
		}
	}

	_, pubPoly := crypto.NewTBLSPoly(m)

	return Manifest{
		TSS:     crypto.TBLSScheme{PubPoly: pubPoly},
		Members: members,
		ENRs:    enrs,
	}, p2pKeys, blsKeys
}

// availableLocalAddr returns an available local tcp address.
func availableLocalAddr(t *testing.T) *net.TCPAddr {
	t.Helper()

	l, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	require.NoError(t, l.Close())

	addr, err := net.ResolveTCPAddr(l.Addr().Network(), l.Addr().String())
	require.NoError(t, err)

	return addr
}
