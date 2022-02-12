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

package types

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/rlp"
	libp2pcrypto "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/crypto/bls"
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

// NewPeer returns a new peer from an
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

// Manifest defines a charon cluster. The same manifest is loaded by all charon nodes in the cluster.
type Manifest struct {
	// TSS is the threshold signature scheme  of the cluster.
	TSS bls.TSS
	// Peers is set of charon nodes in the cluster.
	Peers []Peer
}

// ENRs returns the peer ENRs.
func (m Manifest) ENRs() []enr.Record {
	res := make([]enr.Record, 0, len(m.Peers))

	for _, p := range m.Peers {
		res = append(res, p.ENR)
	}

	return res
}

// PeerIDs returns the peer IDs.
func (m Manifest) PeerIDs() []peer.ID {
	res := make([]peer.ID, 0, len(m.Peers))

	for _, p := range m.Peers {
		res = append(res, p.ID)
	}

	return res
}

func (m Manifest) MarshalJSON() ([]byte, error) {
	var enrs []string
	for _, p := range m.Peers {
		enrStr, err := EncodeENR(p.ENR)
		if err != nil {
			return nil, err
		}

		enrs = append(enrs, enrStr)
	}

	var verifiers [][]byte
	for _, c := range m.TSS.Verifier.Commitments {
		verifiers = append(verifiers, c.ToAffineCompressed())
	}

	rawPK, err := m.TSS.PubKey.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "marshal pubkey")
	}

	return json.Marshal(manifestJSON{
		PubKey:    hex.EncodeToString(rawPK),
		Verifiers: verifiers,
		PeerENRs:  enrs,
	})
}

func (m *Manifest) UnmarshalJSON(data []byte) error {
	var mj manifestJSON
	if err := json.Unmarshal(data, &mj); err != nil {
		return errors.Wrap(err, "unmarshal manifest")
	}

	var peers []Peer
	for i, enrStr := range mj.PeerENRs {
		record, err := DecodeENR(enrStr)
		if err != nil {
			return err
		}

		var pubkey enode.Secp256k1
		if err := record.Load(&pubkey); err != nil {
			return errors.Wrap(err, "pubkey from enr")
		}

		p2pPubkey := libp2pcrypto.Secp256k1PublicKey(pubkey)
		id, err := peer.IDFromPublicKey(&p2pPubkey)
		if err != nil {
			return errors.Wrap(err, "p2p id from pubkey")
		}

		peers = append(peers, Peer{
			ENR:   record,
			ID:    id,
			Index: i,
		})
	}

	var commitments []curves.Point
	for _, vbytes := range mj.Verifiers {
		c, err := curves.BLS12381G1().Point.FromAffineCompressed(vbytes)
		if err != nil {
			return errors.Wrap(err, "verifier hex")
		}

		commitments = append(commitments, c)
	}

	b, err := hex.DecodeString(mj.PubKey)
	if err != nil {
		return errors.Wrap(err, "pubkey hex")
	}

	pk := new(bls_sig.PublicKey)
	if err := pk.UnmarshalBinary(b); err != nil {
		return errors.Wrap(err, "unmarshal pubkey")
	}

	*m = Manifest{
		TSS: bls.TSS{
			PubKey: pk,
			Verifier: &sharing.FeldmanVerifier{
				Commitments: commitments,
			},
			NumShares: len(mj.PeerENRs),
		},
		Peers: peers,
	}

	return nil
}

type manifestJSON struct {
	PubKey    string   `json:"pubkey"`
	Verifiers [][]byte `json:"verifiers"`
	PeerENRs  []string `json:"peers"`
}

// EncodeENR returns an encoded string format of the enr record.
func EncodeENR(record enr.Record) (string, error) {
	var buf bytes.Buffer
	if err := record.EncodeRLP(&buf); err != nil {
		return "", err
	}

	return "enr:" + base64.URLEncoding.EncodeToString(buf.Bytes()), nil
}

// DecodeENR returns a enr record decoded from the string.
// See reference github.com/ethereum/go-ethereum@v1.10.10/p2p/dnsdisc/tree.go:378
func DecodeENR(enrStr string) (enr.Record, error) {
	enrStr = strings.TrimPrefix(enrStr, "enr:")
	enrBytes, err := base64.URLEncoding.DecodeString(enrStr)
	if err != nil {
		return enr.Record{}, errors.Wrap(err, "base64 enr")
	}

	var record enr.Record
	if err := rlp.DecodeBytes(enrBytes, &record); err != nil {
		return enr.Record{}, errors.Wrap(err, "rlp enr")
	}

	return record, nil
}
