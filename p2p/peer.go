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
