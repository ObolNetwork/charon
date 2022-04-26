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

package app

import (
	"encoding/json"
	"fmt"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/libp2p/go-libp2p-core/peer"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
)

const manifestVersion = "obol/charon/manifest/0.0.1"

// NodeIdx represents the index of a node/peer/share in the cluster as defined in the manifest.
type NodeIdx struct {
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

// NodeIdx returns the node index for the peer.
func (m Manifest) NodeIdx(pID peer.ID) (NodeIdx, error) {
	for i, p := range m.Peers {
		if p.ID != pID {
			continue
		}

		return NodeIdx{
			PeerIdx:  i,     // 0-indexed
			ShareIdx: i + 1, // 1-indexed
		}, nil
	}

	return NodeIdx{}, errors.New("unknown peer id")
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

		p, err := p2p.NewPeer(record, i)
		if err != nil {
			return err
		}

		peers = append(peers, p)
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
