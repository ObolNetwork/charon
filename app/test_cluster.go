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

package app

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
	crypto2 "github.com/obolnetwork/charon/tbls"
)

// NewClusterForT returns a new cluster manifest with dv number of distributed validators, k threshold and n peers.
// It also returns the peer p2p keys and BLS secret shares. If the seed is zero a random cluster on available loopback
// ports is generated, else a deterministic cluster is generated.
// Note this is not defined in testutil since it is tightly coupled with the app package.
func NewClusterForT(t *testing.T, dv, k, n, seed int) (Manifest, []*ecdsa.PrivateKey, [][]*bls_sig.SecretKeyShare) {
	t.Helper()

	var (
		dvs      []crypto2.TSS
		dvShares [][]*bls_sig.SecretKeyShare
		p2pKeys  []*ecdsa.PrivateKey
		peers    []p2p.Peer
	)

	addrFunc := getAddrFunc(seed)

	random := io.Reader(rand.New(rand.NewSource(int64(seed)))) //nolint:gosec // Explicit use of weak random generator for determinism.
	if seed == 0 {
		random = crand.Reader
	}

	for i := 0; i < dv; i++ {
		tss, shares, err := crypto2.GenerateTSS(k, n, random)
		require.NoError(t, err)

		dvs = append(dvs, tss)
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

		peer, err := p2p.NewPeer(r, i)
		require.NoError(t, err)

		peers = append(peers, peer)
		p2pKeys = append(p2pKeys, p2pKey)
	}

	return Manifest{
		DVs:   dvs,
		Peers: peers,
	}, p2pKeys, dvShares
}

// getAddrFunc returns either actual available ports for zero seeds
// or deterministic addresses for non-zero seeds.
func getAddrFunc(seed int) func(*testing.T) *net.TCPAddr {
	if seed == 0 {
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
