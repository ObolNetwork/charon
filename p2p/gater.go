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
	"github.com/libp2p/go-libp2p-core/connmgr"
	"github.com/libp2p/go-libp2p-core/control"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/multiformats/go-multiaddr"
)

// ConnGater filters incoming connections by the cluster peers.
type ConnGater struct {
	peerIDs map[peer.ID]bool
}

var _ connmgr.ConnectionGater = ConnGater{}

// NewConnGater return a new connection gater that limits access to the cluster peers.
func NewConnGater(peers []peer.ID) (ConnGater, error) {
	peerMap := make(map[peer.ID]bool)
	for _, peerID := range peers {
		peerMap[peerID] = true
	}

	return ConnGater{
		peerIDs: peerMap,
	}, nil
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
	return c.peerIDs[id]
}

// InterceptUpgraded does nothing.
func (ConnGater) InterceptUpgraded(_ network.Conn) (bool, control.DisconnectReason) {
	return true, 0
}
