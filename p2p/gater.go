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
	"github.com/libp2p/go-libp2p-core/connmgr"
	"github.com/libp2p/go-libp2p-core/control"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/multiformats/go-multiaddr"
)

var _ connmgr.ConnectionGater = ConnGater{}

// NewConnGater return a new connection gater that limits access to the cluster peers and relays.
func NewConnGater(peers []peer.ID, relays []Peer) (ConnGater, error) {
	peerMap := make(map[peer.ID]bool)
	for _, peerID := range peers {
		peerMap[peerID] = true
	}

	// Allow connections to/from relays.
	for _, relay := range relays {
		peerMap[relay.ID] = true
	}

	return ConnGater{
		peerIDs: peerMap,
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
	open    bool
}

// InterceptPeerDial does nothing.
func (ConnGater) InterceptPeerDial(_ peer.ID) (allow bool) {
	return true // don't filter peer dials
}

func (ConnGater) InterceptAddrDial(_ peer.ID, _ multiaddr.Multiaddr) (allow bool) {
	// TODO should limit dialing to the netlist
	return true // don't filter address dials
}

func (ConnGater) InterceptAccept(_ network.ConnMultiaddrs) (allow bool) {
	// TODO should limit accepting from the netlist
	return true // don't filter incoming connections purely by address
}

// InterceptSecured rejects nodes with a peer ID that isn't part of any known DV.
func (c ConnGater) InterceptSecured(_ network.Direction, id peer.ID, _ network.ConnMultiaddrs) bool {
	if c.open {
		return true
	}

	return c.peerIDs[id]
}

// InterceptUpgraded does nothing.
func (ConnGater) InterceptUpgraded(_ network.Conn) (bool, control.DisconnectReason) {
	return true, 0
}
