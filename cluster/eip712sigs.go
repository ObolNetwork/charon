// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster

import (
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/eip712"
)

// eip712Type defines the EIP712 (https://eips.ethereum.org/EIPS/eip-712) Primary type and the Message field and value.
type eip712Type struct {
	PrimaryType string
	Field       string
	ValueFunc   func(Definition, Operator) string
}

var (
	// eip712CreatorConfigHash defines the EIP712 structure of the legacy config signature for v1.4 and later.
	eip712CreatorConfigHash = eip712Type{
		PrimaryType: "CreatorConfigHash",
		Field:       "creator_config_hash",
		ValueFunc: func(definition Definition, _ Operator) string {
			return to0xHex(definition.ConfigHash)
		},
	}

	// eip712OperatorConfigHash defines the EIP712 structure of the operator config signature for v1.4 and later.
	eip712OperatorConfigHash = eip712Type{
		PrimaryType: "OperatorConfigHash",
		Field:       "operator_config_hash",
		ValueFunc: func(definition Definition, _ Operator) string {
			return to0xHex(definition.ConfigHash)
		},
	}

	// eip712V1x3ConfigHash defines the EIP712 structure of the legacy config signature for v1.3 and before.
	eip712V1x3ConfigHash = eip712Type{
		PrimaryType: "ConfigHash",
		Field:       "config_hash",
		ValueFunc: func(definition Definition, _ Operator) string {
			return to0xHex(definition.ConfigHash)
		},
	}

	// eip712ENR defines the EIP712 structure of the enr signature.
	eip712ENR = eip712Type{
		PrimaryType: "ENR",
		Field:       "enr",
		ValueFunc: func(_ Definition, operator Operator) string {
			return operator.ENR
		},
	}
)

// getOperatorEIP712Type returns the latest or legacy operator eip712 type.
func getOperatorEIP712Type(version string) eip712Type {
	if !supportEIP712Sigs(version) {
		panic("invalid eip712 signature version") // This should never happen
	}

	if isAnyVersion(version, v1_3) {
		return eip712V1x3ConfigHash
	}

	return eip712OperatorConfigHash
}

// digestEIP712 returns the digest for the EIP712 structured type for the provided definition and operator.
func digestEIP712(typ eip712Type, def Definition, operator Operator) ([]byte, error) {
	chainID, err := eth2util.ForkVersionToChainID(def.ForkVersion)
	if err != nil {
		return nil, err
	}

	data := eip712.TypedData{
		Domain: eip712.Domain{
			Name:    "Obol",
			Version: "1",
			ChainID: chainID,
		},
		Type: eip712.Type{
			Name: typ.PrimaryType,
			Fields: []eip712.Field{
				{
					Name:  typ.Field,
					Type:  eip712.PrimitiveString,
					Value: typ.ValueFunc(def, operator),
				},
			},
		},
	}

	digest, err := eip712.HashTypedData(data)
	if err != nil {
		return nil, errors.Wrap(err, "hash EIP712")
	}

	return digest, nil
}

// signEIP712 returns the EIP712 signature for the primary type.
func signEIP712(secret *k1.PrivateKey, typ eip712Type, def Definition, operator Operator) ([]byte, error) {
	digest, err := digestEIP712(typ, def, operator)
	if err != nil {
		return nil, err
	}

	sig, err := k1util.Sign(secret, digest)
	if err != nil {
		return nil, errors.Wrap(err, "sign EIP712")
	}

	return sig, nil
}
