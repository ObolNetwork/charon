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
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/p2p"
)

// Operator identifies the operator of a charon node and its ENR.
// Note the following struct tag meanings:
//   - json: json field name. Suffix 0xhex indicates bytes are formatted as 0x prefixed hex strings.
//   - ssz: ssz equivalent. Either uint64 for numbers, BytesN for fixed length bytes, ByteList[MaxN]
//     for variable length strings, or CompositeList[MaxN] for nested object arrays.
//   - config_hash: field ordering when calculating config hash. Some fields are excluded indicated by `-`.
//   - definition_hash: field ordering when calculating definition hash. Some fields are excluded indicated by `-`.
type Operator struct {
	// The 20 byte Ethereum address of the operator
	Address string `json:"address,0xhex" ssz:"Bytes20" config_hash:"0" definition_hash:"0"`

	// ENR identifies the charon node. Max 1024 chars.
	ENR string `json:"enr" ssz:"ByteList[1024]" config_hash:"-" definition_hash:"1"`

	// ConfigSignature is an EIP712 signature of the config_hash using privkey corresponding to operator Ethereum Address.
	ConfigSignature []byte `json:"config_signature,0xhex" ssz:"Bytes65" config_hash:"-" definition_hash:"2"`

	// ENRSignature is a EIP712 signature of the ENR by the Address, authorising the charon node to act on behalf of the operator in the cluster.
	ENRSignature []byte `json:"enr_signature,0xhex" ssz:"Bytes65" config_hash:"-" definition_hash:"3"`
}

// Peer returns the p2p peer for operator based on its ENR.
func (o Operator) Peer() (p2p.Peer, error) {
	enr, err := p2p.DecodeENR(o.ENR)
	if err != nil {
		return p2p.Peer{}, errors.Wrap(err, "decode enr", z.Str("enr", o.ENR))
	}

	return p2p.NewPeer(enr, 0)
}

// operatorJSONv1x1 is the json formatter of Operator for versions v1.0.0 and v1.1.0.
type operatorJSONv1x1 struct {
	Address         string `json:"address"`
	ENR             string `json:"enr"`
	Nonce           int    `json:"nonce"` // Always 0
	ConfigSignature []byte `json:"config_signature"`
	ENRSignature    []byte `json:"enr_signature"`
}

// operatorJSONv1x2orLater is the json formatter of Operator for versions v1.2.
type operatorJSONv1x2orLater struct {
	Address         string `json:"address"`
	ENR             string `json:"enr"`
	ConfigSignature ethHex `json:"config_signature"`
	ENRSignature    ethHex `json:"enr_signature"`
}

func operatorsFromV1x1(operators []operatorJSONv1x1) ([]Operator, error) {
	var resp []Operator
	for _, o := range operators {
		if o.Nonce != 0 {
			return nil, errors.New("non-zero operator nonce not supported")
		}

		resp = append(resp, Operator{
			Address:         o.Address,
			ENR:             o.ENR,
			ConfigSignature: o.ConfigSignature,
			ENRSignature:    o.ENRSignature,
		})
	}

	return resp, nil
}

func operatorsToV1x1(operators []Operator) []operatorJSONv1x1 {
	var resp []operatorJSONv1x1
	for _, o := range operators {
		resp = append(resp, operatorJSONv1x1{
			Address:         o.Address,
			ENR:             o.ENR,
			Nonce:           zeroNonce,
			ConfigSignature: o.ConfigSignature,
			ENRSignature:    o.ENRSignature,
		})
	}

	return resp
}

func operatorsFromV1x2orLater(operators []operatorJSONv1x2orLater) []Operator {
	var resp []Operator
	for _, o := range operators {
		resp = append(resp, Operator{
			Address:         o.Address,
			ENR:             o.ENR,
			ConfigSignature: o.ConfigSignature,
			ENRSignature:    o.ENRSignature,
		})
	}

	return resp
}

func operatorsToV1x2orLater(operators []Operator) []operatorJSONv1x2orLater {
	var resp []operatorJSONv1x2orLater
	for _, o := range operators {
		resp = append(resp, operatorJSONv1x2orLater{
			Address:         o.Address,
			ENR:             o.ENR,
			ConfigSignature: o.ConfigSignature,
			ENRSignature:    o.ENRSignature,
		})
	}

	return resp
}
