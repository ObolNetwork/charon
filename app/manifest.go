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

package app

import (
	"encoding/json"
	"fmt"

	"github.com/dB2510/kryptology/pkg/core/curves"
	"github.com/dB2510/kryptology/pkg/sharing"
	"github.com/dB2510/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	libp2pcrypto "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
)

const manifestVersion = "obol/charon/manifest/0.0.1"

// ClusterIdx represents the index of a node/peer/share in the cluster as defined in the manifest.
type ClusterIdx struct {
	// PeerID is ID of this peers.
	PeerID peer.ID
	// PeerIdx is the index of a peer in the peer list (it 0-indexed).
	PeerIdx int
	// ShareIdx is the tbls share identifier (it is 1-indexed).
	ShareIdx int
}

// Manifest defines a charon cluster. The same manifest is loaded by all charon nodes in the cluster.
// TODO(corver): Add authentication signatures for each peer per DV.
type Manifest struct {
	// DVs is the set of distributed validators managed by the cluster.
	// Each DV is defined by its threshold signature scheme.
	DVs []tbls.TSS

	// Peers is set of charon nodes in the cluster.
	Peers []p2p.Peer
}

// ENRs is a convenience function that returns the peer ENRs.
func (m Manifest) ENRs() []enr.Record {
	res := make([]enr.Record, 0, len(m.Peers))

	for _, p := range m.Peers {
		res = append(res, p.ENR)
	}

	return res
}

// PeerIDs is a convenience function that returns the peer IDs.
func (m Manifest) PeerIDs() []peer.ID {
	res := make([]peer.ID, 0, len(m.Peers))

	for _, p := range m.Peers {
		res = append(res, p.ID)
	}

	return res
}

// ClusterIdx returns the cluster index for the peer.
func (m Manifest) ClusterIdx(pID peer.ID) (ClusterIdx, error) {
	for i, p := range m.Peers {
		if p.ID != pID {
			continue
		}

		return ClusterIdx{
			PeerIdx:  i,
			PeerID:   pID,
			ShareIdx: i + 1,
		}, nil
	}

	return ClusterIdx{}, errors.New("unknown peer id")
}

// PublicKeys is a convenience function that returns the DV root public keys.
func (m Manifest) PublicKeys() []*bls_sig.PublicKey {
	res := make([]*bls_sig.PublicKey, 0, len(m.DVs))

	for _, tss := range m.DVs {
		res = append(res, tss.PublicKey())
	}

	return res
}

func (m Manifest) MarshalJSON() ([]byte, error) {
	var enrs []string
	for _, p := range m.Peers {
		enrStr, err := p2p.EncodeENR(p.ENR)
		if err != nil {
			return nil, err
		}

		enrs = append(enrs, enrStr)
	}

	var dvs []dvJSON
	for _, tss := range m.DVs {
		if len(m.Peers) != tss.NumShares() {
			return nil, errors.New("dv shares and peers mismatch")
		}

		var verifiers [][]byte
		for _, c := range tss.Verifier().Commitments {
			verifiers = append(verifiers, c.ToAffineCompressed())
		}

		rawPK, err := tss.PublicKey().MarshalBinary()
		if err != nil {
			return nil, errors.Wrap(err, "marshal pubkey")
		}

		dvs = append(dvs, dvJSON{
			PubKey:    fmt.Sprintf("%#x", rawPK),
			Verifiers: verifiers,
		})
	}

	res, err := json.Marshal(manifestJSON{
		Version:     manifestVersion,
		Description: getDescription(m),
		DVs:         dvs,
		PeerENRs:    enrs,
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal manifest")
	}

	return res, nil
}

func (m *Manifest) UnmarshalJSON(data []byte) error {
	var mjson manifestJSON
	if err := json.Unmarshal(data, &mjson); err != nil {
		return errors.Wrap(err, "unmarshal manifest")
	}

	if mjson.Version != manifestVersion {
		return errors.New("invalid manifest version")
	}

	var peers []p2p.Peer
	for i, enrStr := range mjson.PeerENRs {
		record, err := p2p.DecodeENR(enrStr)
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

		peers = append(peers, p2p.Peer{
			ENR:   record,
			ID:    id,
			Index: i,
		})
	}

	var dvs []tbls.TSS
	for _, dv := range mjson.DVs {
		var commitments []curves.Point
		for _, vBytes := range dv.Verifiers {
			c, err := curves.BLS12381G1().Point.FromAffineCompressed(vBytes)
			if err != nil {
				return errors.Wrap(err, "verifier hex")
			}

			commitments = append(commitments, c)
		}

		tss, err := tbls.NewTSS(
			&sharing.FeldmanVerifier{Commitments: commitments},
			len(mjson.PeerENRs),
		)
		if err != nil {
			return err
		}

		dvs = append(dvs, tss)
	}

	*m = Manifest{
		DVs:   dvs,
		Peers: peers,
	}

	return nil
}

type manifestJSON struct {
	Version     string   `json:"version"`
	Description string   `json:"description"`
	DVs         []dvJSON `json:"distributed_validators"`
	PeerENRs    []string `json:"peers"`
}

type dvJSON struct {
	PubKey    string   `json:"root_pubkey"`
	Verifiers [][]byte `json:"threshold_verifiers"`
}

func getDescription(m Manifest) string {
	dv := len(m.DVs)
	peers := len(m.Peers)

	var threshold int
	if dv > 0 {
		threshold = m.DVs[0].Threshold()
	}

	return fmt.Sprintf("dv/%d/threshold/%d/peer/%d", dv, threshold, peers)
}
