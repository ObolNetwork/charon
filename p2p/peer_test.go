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

package p2p_test

import (
	"crypto/ecdsa"
	"math/rand"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/p2p"
)

func TestNewPeer(t *testing.T) {
	p2pKey, err := ecdsa.GenerateKey(crypto.S256(), rand.New(rand.NewSource(0)))
	require.NoError(t, err)

	var r enr.Record
	r.SetSeq(0)

	err = enode.SignV4(&r, p2pKey)
	require.NoError(t, err)

	p, err := p2p.NewPeer(r, 0)
	require.NoError(t, err)

	require.Equal(t, "16Uiu2HAm87ieJpGmqjdqVF6Y4LAodxdsUY2sVCX5b31QVHCLt116", p.ID.Pretty())
}

func TestNewHost(t *testing.T) {
	privKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	_, err = p2p.NewTCPNode(p2p.Config{}, privKey, p2p.NewOpenGater(), nil, nil, nil)
	require.NoError(t, err)
}

func TestVerifyP2PKey(t *testing.T) {
	lock, keys, _ := cluster.NewForT(t, 1, 3, 4, 0)

	peers, err := lock.Peers()
	require.NoError(t, err)

	for _, key := range keys {
		require.NoError(t, p2p.VerifyP2PKey(peers, key))
	}

	key, err := ecdsa.GenerateKey(crypto.S256(), rand.New(rand.NewSource(time.Now().Unix())))
	require.NoError(t, err)
	require.Error(t, p2p.VerifyP2PKey(peers, key))
}
