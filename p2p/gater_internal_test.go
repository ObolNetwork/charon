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

package p2p

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"testing"

	gcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/stretchr/testify/require"
)

func TestInterceptSecured(t *testing.T) {
	c := ConnGater{
		peerIDs: map[peer.ID]bool{},
	}
	tests := map[string]struct {
		peerID         peer.ID
		expected       bool
		setPeerToKnown bool
		logMsg         string
	}{
		"unknown peer": {"unknown_peer_id", false, false, "should reject connection attempt from unknown peers"},
		"known peer":   {"known_peer_id", true, true, "should accept connection attempt from known peers"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if tc.setPeerToKnown {
				c.peerIDs[tc.peerID] = true
			}
			allow := c.InterceptSecured(0, tc.peerID, nil)
			require.Equal(t, tc.expected, allow, tc.logMsg)
		})
	}
}

// Tests if node A rejects connection attempt from unknown node B.
func TestP2PConnGating(t *testing.T) {
	c := ConnGater{
		peerIDs: map[peer.ID]bool{},
	}

	// create node A
	p2pConfigA := Config{TCPAddrs: []string{"127.0.0.1:3030"}}
	prvKeyA, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	if err != nil {
		t.Fatal("private key generation for A failed", err)
	}
	nodeA, err := NewTCPNode(p2pConfigA, convertPrivKey(prvKeyA), c, UDPNode{}, nil, DefaultAdvertisedAddrs)
	if err != nil {
		t.Fatal("couldn't instantiate new node A", err)
	}

	// create node B
	p2pConfigB := Config{TCPAddrs: []string{"127.0.0.1:3031"}}
	prvKeyB, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	if err != nil {
		t.Fatal("private key generation for B failed", err)
	}
	nodeB, err := NewTCPNode(p2pConfigB, convertPrivKey(prvKeyB), c, UDPNode{}, nil, DefaultAdvertisedAddrs)
	if err != nil {
		t.Fatal("couldn't instantiate new node B", err)
	}

	// Let B attempt connection to A
	err = nodeB.Connect(context.Background(), peer.AddrInfo{ID: nodeA.ID(), Addrs: nodeA.Addrs()})
	require.Error(t, err)
	require.Contains(t, err.Error(), fmt.Sprintf("gater rejected connection with peer %s and addr %s", nodeA.ID(), nodeA.Addrs()[0]))
}

func TestOpenGater(t *testing.T) {
	gater := NewOpenGater()
	require.True(t, gater.InterceptSecured(0, "", nil))
}

func convertPrivKey(privkey crypto.PrivKey) *ecdsa.PrivateKey {
	typeAssertedKey := (*ecdsa.PrivateKey)(privkey.(*crypto.Secp256k1PrivateKey))
	typeAssertedKey.Curve = gcrypto.S256() // Temporary hack, so libp2p Secp256k1 is recognized as geth Secp256k1 in disc v5.1.

	return typeAssertedKey
}
