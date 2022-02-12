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

package types

import (
	"crypto/ecdsa"
	"math/rand"
	"net"
	"testing"

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/crypto/bls"
)

// NewClusterForT returns a new random cluster manifest with threshold m and size n.
// It also returns the peer p2p keys and BLS secret shares.
// Note that the threshold signatures are stubs at this point.
func NewClusterForT(t *testing.T, m, n int, seed int64) (Manifest, []*ecdsa.PrivateKey, []*bls_sig.SecretKeyShare) {
	t.Helper()

	var (
		p2pKeys []*ecdsa.PrivateKey
		peers   []Peer
	)

	reader := rand.New(rand.NewSource(seed))

	tss, shares, err := bls.GenerateTSS(m, n, reader)
	require.NoError(t, err)

	addrFunc := getAddrFunc(seed)

	for i := 0; i < n; i++ {
		// Generate ENR
		p2pKey, err := ecdsa.GenerateKey(secp256k1.S256(), reader)
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

		peer, err := NewPeer(r, i)
		require.NoError(t, err)

		peers = append(peers, peer)
		p2pKeys = append(p2pKeys, p2pKey)
	}

	return Manifest{
		DVs:   []bls.TSS{tss}, // TODO(corver): Support more dvs per cluster.
		Peers: peers,
	}, p2pKeys, shares
}

// getAddrFunc returns either actual available ports for timestamp seeds
// or deterministic addresses for non-timestamp seeds.
func getAddrFunc(seed int64) func(*testing.T) *net.TCPAddr {
	if seed > 1e6 {
		return availableLocalAddr
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
