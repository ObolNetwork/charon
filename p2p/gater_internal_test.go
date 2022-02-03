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

package p2p

import (
	"context"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/stretchr/testify/require"
)

func TestInterceptSecured(t *testing.T) {
	c := ConnGater{
		PeerIDs:  map[peer.ID]struct{}{},
		Networks: nil,
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
				c.PeerIDs[tc.peerID] = struct{}{}
			}
			allow := c.InterceptSecured(0, tc.peerID, nil)
			require.Equal(t, tc.expected, allow, tc.logMsg)
		})
	}
}

// Tests if node A rejects connection attempt from unknown node B.
func TestP2PConnGating(t *testing.T) {
	c := ConnGater{
		PeerIDs:  map[peer.ID]struct{}{},
		Networks: nil,
	}

	// create node A
	p2pConfigA := Config{Addrs: []string{"127.0.0.1:3030"}}
	prvKeyA, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	if err != nil {
		t.Fatal("private key generation for A failed", err)
	}
	nodeA, err := NewNode(p2pConfigA, convertInterfaceToPrivKey(prvKeyA), c)
	if err != nil {
		t.Fatal("couldn't instantiate new node A", err)
	}

	// create node B
	p2pConfigB := Config{Addrs: []string{"127.0.0.1:3031"}}
	prvKeyB, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	if err != nil {
		t.Fatal("private key generation for B failed", err)
	}
	nodeB, err := NewNode(p2pConfigB, convertInterfaceToPrivKey(prvKeyB), c)
	if err != nil {
		t.Fatal("couldn't instantiate new node B", err)
	}

	// Let B attempt connection to A
	err = nodeB.Connect(context.Background(), peer.AddrInfo{ID: nodeA.ID(), Addrs: nodeA.Addrs()})
	require.Error(t, err)
	require.Contains(t, err.Error(), fmt.Sprintf("gater rejected connection with peer %s and addr %s", nodeA.ID(), nodeA.Addrs()[0]))
}
