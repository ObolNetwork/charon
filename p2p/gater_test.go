package p2p

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
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

// Tests if node A rejects connection attempt from unknown node B
func TestP2PConnGating(t *testing.T) {
	c := ConnGater{
		PeerIDs:  map[peer.ID]struct{}{},
		Networks: nil,
	}

	// create node A
	p2pConfigA := &Config{[]net.IP{net.ParseIP("127.0.0.1")}, 3030, nil}
	prvKeyA, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	if err != nil {
		t.Fatal("private key generation for A failed", err)
	}
	nodeA, err := NewNode(p2pConfigA, convertInterfaceToPrivKey(prvKeyA), &c)
	if err != nil {
		t.Fatal("couldn't instantiate new node A", err)
	}

	// create node B
	p2pConfigB := &Config{[]net.IP{net.ParseIP("127.0.0.1")}, 3031, nil}
	prvKeyB, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	if err != nil {
		t.Fatal("private key generation for B failed", err)
	}
	nodeB, err := NewNode(p2pConfigB, convertInterfaceToPrivKey(prvKeyB), &c)
	if err != nil {
		t.Fatal("couldn't instantiate new node B", err)
	}

	// Let B attempt connection to A
	err = nodeB.Connect(context.Background(), peer.AddrInfo{ID: nodeA.ID(), Addrs: nodeA.Addrs()})
	require.Error(t, err)
	require.Contains(t, err.Error(), fmt.Sprintf("gater rejected connection with peer %s and addr %s", nodeA.ID(), nodeA.Addrs()[0]))
}
