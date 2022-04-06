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
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	libp2pcrypto "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"

	"github.com/obolnetwork/charon/app/errors"
)

// Peer represents a charon node in a cluster.
type Peer struct {
	// ENR defines the networking information of the peer.
	ENR enr.Record

	// ID is a libp2p peer identity. It is inferred from the ENR.
	ID peer.ID

	// Index is the order of this node in the cluster.
	Index int
}

// NewPeer returns a new peer from an.
func NewPeer(record enr.Record, index int) (Peer, error) {
	var pubkey enode.Secp256k1
	if err := record.Load(&pubkey); err != nil {
		return Peer{}, errors.Wrap(err, "pubkey from enr")
	}

	p2pPubkey := libp2pcrypto.Secp256k1PublicKey(pubkey)
	id, err := peer.IDFromPublicKey(&p2pPubkey)
	if err != nil {
		return Peer{}, errors.Wrap(err, "p2p id from pubkey")
	}

	return Peer{
		ENR:   record,
		ID:    id,
		Index: index,
	}, nil
}
