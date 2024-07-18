// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

// BuilderFalse is a core.BuilderEnabled function that always returns false.
var BuilderFalse = func(slot uint64) bool { return false } //nolint:revive // keep slot variable name for clarity

// BuilderTrue is a core.BuilderEnabled function that always returns true.
var BuilderTrue = func(slot uint64) bool { return true } //nolint:revive // keep slot variable name for clarity

// NewTCPNodeCallback returns a callback that can be used to connect a TCP node to all other TCP nodes.
func NewTCPNodeCallback(t *testing.T, protocols ...protocol.ID) func(host host.Host) {
	t.Helper()
	var tcpNodesLock sync.Mutex
	var tcpNodes []host.Host

	return func(tcpNode host.Host) {
		tcpNodesLock.Lock()
		defer tcpNodesLock.Unlock()

		for _, other := range tcpNodes {
			other.Peerstore().AddAddrs(tcpNode.ID(), tcpNode.Addrs(), peerstore.PermanentAddrTTL)
			err := other.Peerstore().AddProtocols(tcpNode.ID(), protocols...)
			require.NoError(t, err)

			tcpNode.Peerstore().AddAddrs(other.ID(), other.Addrs(), peerstore.PermanentAddrTTL)
			err = tcpNode.Peerstore().AddProtocols(other.ID(), protocols...)
			require.NoError(t, err)
		}

		tcpNodes = append(tcpNodes, tcpNode)
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
