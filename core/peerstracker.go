// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core

import (
	"sync"

	"github.com/libp2p/go-libp2p/core/peer"
)

type peersTracker struct {
	sync.RWMutex

	unreachable map[peer.ID]struct{}
}

var _ PeersTracker = (*peersTracker)(nil)

func NewPeersTracker() PeersTracker {
	return &peersTracker{
		unreachable: make(map[peer.ID]struct{}),
	}
}

func (pt *peersTracker) SetAlive(peerID peer.ID) {
	pt.Lock()
	defer pt.Unlock()

	delete(pt.unreachable, peerID)
}

func (pt *peersTracker) SetUnreachable(peerID peer.ID) {
	pt.Lock()
	defer pt.Unlock()

	pt.unreachable[peerID] = struct{}{}
}

func (pt *peersTracker) Unreachable() []peer.ID {
	pt.RLock()
	defer pt.RUnlock()

	var unreachable []peer.ID
	for p := range pt.unreachable {
		unreachable = append(unreachable, p)
	}

	return unreachable
}
