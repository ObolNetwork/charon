// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p

import (
	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

var _ connmgr.ConnectionGater = ConnGater{}

// NewConnGater return a new connection gater that limits access to the cluster peers and relays.
func NewConnGater(peers []peer.ID, relays []*MutablePeer) (ConnGater, error) {
	peerMap := make(map[peer.ID]bool)
	for _, peerID := range peers {
		peerMap[peerID] = true
	}

	return ConnGater{
		peerIDs: peerMap,
		relays:  relays,
		open:    false,
	}, nil
}

// NewOpenGater returns a connection gater that is open, not gating any connections.
func NewOpenGater() ConnGater {
	return ConnGater{
		open: true,
	}
}

// ConnGater filters incoming connections by the cluster peers.
type ConnGater struct {
	peerIDs map[peer.ID]bool
	relays  []*MutablePeer
	open    bool
}

// InterceptPeerDial does nothing.
func (ConnGater) InterceptPeerDial(_ peer.ID) (allow bool) {
	return true // don't filter peer dials
}

func (ConnGater) InterceptAddrDial(_ peer.ID, _ multiaddr.Multiaddr) (allow bool) {
	return true // don't filter address dials
}

func (ConnGater) InterceptAccept(_ network.ConnMultiaddrs) (allow bool) {
	return true // don't filter incoming connections purely by address
}

// InterceptSecured rejects nodes with a peer ID that isn't part of any known DV.
func (c ConnGater) InterceptSecured(_ network.Direction, id peer.ID, _ network.ConnMultiaddrs) bool {
	if c.open {
		return true
	}

	if c.peerIDs[id] {
		return true
	}

	for _, relay := range c.relays {
		p, ok := relay.Peer()
		if ok && p.ID == id {
			return true
		}
	}

	return false
}

// InterceptUpgraded does nothing.
func (ConnGater) InterceptUpgraded(_ network.Conn) (bool, control.DisconnectReason) {
	return true, 0
}
