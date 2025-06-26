// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package testutil

import (
	"net"
	"sync"
	"testing"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/stretchr/testify/require"
)

// NewP2PNodeCallback returns a callback that can be used to connect a P2P node to all other P2P nodes.
func NewP2PNodeCallback(t *testing.T, protocols ...protocol.ID) func(host host.Host) {
	t.Helper()

	var (
		p2pNodesLock sync.Mutex
		p2pNodes []host.Host
	)

	return func(p2pNode host.Host) {
		p2pNodesLock.Lock()
		defer p2pNodesLock.Unlock()

		for _, other := range p2pNodes {
			other.Peerstore().AddAddrs(p2pNode.ID(), p2pNode.Addrs(), peerstore.PermanentAddrTTL)
			err := other.Peerstore().AddProtocols(p2pNode.ID(), protocols...)
			require.NoError(t, err)

			p2pNode.Peerstore().AddAddrs(other.ID(), other.Addrs(), peerstore.PermanentAddrTTL)
			err = p2pNode.Peerstore().AddProtocols(other.ID(), protocols...)
			require.NoError(t, err)
		}

		p2pNodes = append(p2pNodes, p2pNode)
	}
}

// GetFreePort returns a free port on the machine on which the test is ran.
func GetFreePort(t *testing.T) int {
	t.Helper()

	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	require.NoError(t, err)
	l, err := net.ListenTCP("tcp", addr)
	require.NoError(t, err)

	defer l.Close()

	port := l.Addr().(*net.TCPAddr).Port

	return port
}
