// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package testutil

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/log"
)

// BuilderFalse is a core.BuilderEnabled function that always returns false.
var BuilderFalse = func(slot int64) bool { return false }

// BuilderTrue is a core.BuilderEnabled function that always returns true.
var BuilderTrue = func(slot int64) bool { return true }

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

// WithTestTopic returns a context with a yellow-background "test" topic.
// Useful to distinguish test logs from application logs.
func WithTestTopic(ctx context.Context) context.Context {
	const testTopic = "test"
	const yellowBackground = 35
	topic := fmt.Sprintf("\x1b[%dm%s\x1b[0m", yellowBackground, testTopic)

	return log.WithTopic(ctx, topic)
}
