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
	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	libp2pcrypto "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"

	"github.com/obolnetwork/charon/app/errors"
)

const PeerCtxKey = "peer"

// Peer represents a peer in the libp2p network, either a charon node or a relay.
type Peer struct {
	// ENR defines the networking information of the peer.
	ENR enr.Record

	// Enode represents the networking host of the peer.
	Enode enode.Node

	// ID is a libp2p peer identity. It is inferred from the ENR.
	ID peer.ID

	// Index is the order of this node in the cluster.
	// This is only applicable to charon nodes, not relays.
	Index int

	// Name represents a human friendly name for the peer.
	Name string
}

// NewPeer returns a new charon peer.
func NewPeer(record enr.Record, index int) (Peer, error) {
	var enodePubkey enode.Secp256k1
	if err := record.Load(&enodePubkey); err != nil {
		return Peer{}, errors.Wrap(err, "pubkey from enr")
	}

	ecdsaPubkey := ecdsa.PublicKey(enodePubkey)
	p2pPubkey, err := libp2pcrypto.UnmarshalSecp256k1PublicKey(crypto.CompressPubkey(&ecdsaPubkey))
	if err != nil {
		return Peer{}, errors.Wrap(err, "convert pubkey")
	}

	id, err := peer.IDFromPublicKey(p2pPubkey)
	if err != nil {
		return Peer{}, errors.Wrap(err, "p2p id from pubkey")
	}

	node, err := enode.New(new(enode.V4ID), &record)
	if err != nil {
		return Peer{}, errors.Wrap(err, "new peer enode")
	}

	return Peer{
		ENR:   record,
		Enode: *node,
		ID:    id,
		Index: index,
		Name:  PeerName(id),
	}, nil
}
