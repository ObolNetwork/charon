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

package cluster

import (
	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/p2p"
)

// Operator identifies a charon node and its operator.
type Operator struct {
	// The Ethereum address of the operator
	Address string

	// ENR identifies the charon node.
	ENR string

	//  Nonce is incremented each time the ENR is added or signed.
	Nonce int

	// ConfigSignature is an EIP712 signature of the config_hash using privkey corresponding to operator Ethereum Address.
	ConfigSignature []byte

	// ENRSignature is a EIP712 signature of the ENR by the Address, authorising the charon node to act on behalf of the operator in the cluster.
	ENRSignature []byte
}

// getName returns a deterministic name for operator based on its ENR.
func (o Operator) getName() (string, error) {
	enr, err := p2p.DecodeENR(o.ENR)
	if err != nil {
		return "", errors.Wrap(err, "decode enr", z.Str("enr", o.ENR))
	}

	peer, err := p2p.NewPeer(enr, 0)
	if err != nil {
		return "", err
	}

	return p2p.PeerName(peer.ID), nil
}

// GetTree ssz hashes the Operator object.
func (o Operator) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(o) //nolint:wrapcheck
}

// HashTreeRoot ssz hashes the Definition object.
func (o Operator) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(o) //nolint:wrapcheck
}

// HashTreeRootWith ssz hashes the Operator object with a hasher.
func (o Operator) HashTreeRootWith(hh ssz.HashWalker) error {
	indx := hh.Index()

	// Field (0) 'Address'
	hh.PutBytes([]byte(o.Address))

	// Field (1) 'ENR'
	hh.PutBytes([]byte(o.ENR))

	// Field (2) 'Nonce'
	hh.PutUint64(uint64(o.Nonce))

	// Field (3) 'ConfigSignature'
	hh.PutBytes(o.ConfigSignature)

	// Field (4) 'ENRSignature'
	hh.PutBytes(o.ENRSignature)

	hh.Merkleize(indx)

	return nil
}

// operatorJSONv1x1 is the json formatter of Operator for versions v1.0.0 and v1.1.0.
type operatorJSONv1x1 struct {
	Address         string `json:"address"`
	ENR             string `json:"enr"`
	Nonce           int    `json:"nonce"`
	ConfigSignature []byte `json:"config_signature"`
	ENRSignature    []byte `json:"enr_signature"`
}

// operatorJSONv1x1 is the json formatter of Operator for versions v1.2 and later.
type operatorJSONv1x2 struct {
	Address         string `json:"address"`
	ENR             string `json:"enr"`
	Nonce           int    `json:"nonce"`
	ConfigSignature ethHex `json:"config_signature"`
	ENRSignature    ethHex `json:"enr_signature"`
}

func operatorsFromV1x1(operators []operatorJSONv1x1) []Operator {
	var resp []Operator
	for _, o := range operators {
		resp = append(resp, Operator{
			Address:         o.Address,
			ENR:             o.ENR,
			Nonce:           o.Nonce,
			ConfigSignature: o.ConfigSignature,
			ENRSignature:    o.ENRSignature,
		})
	}

	return resp
}

func operatorsToV1x1(operators []Operator) []operatorJSONv1x1 {
	var resp []operatorJSONv1x1
	for _, o := range operators {
		resp = append(resp, operatorJSONv1x1{
			Address:         o.Address,
			ENR:             o.ENR,
			Nonce:           o.Nonce,
			ConfigSignature: o.ConfigSignature,
			ENRSignature:    o.ENRSignature,
		})
	}

	return resp
}

func operatorsFromV1x2(operators []operatorJSONv1x2) []Operator {
	var resp []Operator
	for _, o := range operators {
		resp = append(resp, Operator{
			Address:         o.Address,
			ENR:             o.ENR,
			Nonce:           o.Nonce,
			ConfigSignature: o.ConfigSignature,
			ENRSignature:    o.ENRSignature,
		})
	}

	return resp
}

func operatorsToV1x2(operators []Operator) []operatorJSONv1x2 {
	var resp []operatorJSONv1x2
	for _, o := range operators {
		resp = append(resp, operatorJSONv1x2{
			Address:         o.Address,
			ENR:             o.ENR,
			Nonce:           o.Nonce,
			ConfigSignature: o.ConfigSignature,
			ENRSignature:    o.ENRSignature,
		})
	}

	return resp
}
