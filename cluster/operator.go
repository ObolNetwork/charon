// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster

import (
	"github.com/obolnetwork/charon/app/errors"
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
	ENR string `config_hash:"-" definition_hash:"1" json:"enr" ssz:"ByteList[1024]"`

	// ConfigSignature is an EIP712 signature of the config_hash using privkey corresponding to operator Ethereum Address.
	ConfigSignature []byte `json:"config_signature,0xhex" ssz:"Bytes65" config_hash:"-" definition_hash:"2"`

	// ENRSignature is a EIP712 signature of the ENR by the Address, authorising the charon node to act on behalf of the operator in the cluster.
	ENRSignature []byte `json:"enr_signature,0xhex" ssz:"Bytes65" config_hash:"-" definition_hash:"3"`
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
