// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster

import (
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/eip712"
)

// eip712TypeField defines the fields, values and types of a EIP712 message
type eip712TypeField struct {
	Field     string
	Type      eip712.Primitive
	ValueFunc func(Definition, Operator) any
}

// eip712Type defines the EIP712 (https://eips.ethereum.org/EIPS/eip-712) Primary type and the Message fields.
type eip712Type struct {
	PrimaryType string
	Fields      []eip712TypeField
}

var (
	// eip712CreatorConfigHash defines the EIP712 structure of the legacy config signature for v1.4 and later.
	eip712CreatorConfigHash = eip712Type{
		PrimaryType: "CreatorConfigHash",
		Fields: []eip712TypeField{
			{
				Field: "creator_config_hash",
				Type:  eip712.PrimitiveString,
				ValueFunc: func(definition Definition, _ Operator) any {
					return to0xHex(definition.ConfigHash)
				},
			},
		},
	}

	// eip712OperatorConfigHash defines the EIP712 structure of the operator config signature for v1.4 and later.
	eip712OperatorConfigHash = eip712Type{
		PrimaryType: "OperatorConfigHash",
		Fields: []eip712TypeField{
			{
				Field: "operator_config_hash",
				Type:  eip712.PrimitiveString,
				ValueFunc: func(definition Definition, _ Operator) any {
					return to0xHex(definition.ConfigHash)
				},
			},
		},
	}

	// eip712V1x3ConfigHash defines the EIP712 structure of the legacy config signature for v1.3 and before.
	eip712V1x3ConfigHash = eip712Type{
		PrimaryType: "ConfigHash",
		Fields: []eip712TypeField{
			{
				Field: "config_hash",
				Type:  eip712.PrimitiveString,
				ValueFunc: func(definition Definition, _ Operator) any {
					return to0xHex(definition.ConfigHash)
				},
			},
		},
	}

	// eip712ENR defines the EIP712 structure of the enr signature.
	eip712ENR = eip712Type{
		PrimaryType: "ENR",
		Fields: []eip712TypeField{
			{
				Field: "enr",
				Type:  eip712.PrimitiveString,
				ValueFunc: func(_ Definition, operator Operator) any {
					return operator.ENR
				},
			},
		},
	}

	// eip712TermsAndConditions defines the EIP712 structure of the terms and conditions signature.
	eip712TermsAndConditions = eip712Type{
		PrimaryType: "TermsAndConditions",
		Fields: []eip712TypeField{
			{
				Field: "terms_and_conditions_hash",
				Type:  eip712.PrimitiveString,
				ValueFunc: func(_ Definition, _ Operator) any {
					return "0xd33721644e8f3afab1495a74abe3523cec12d48b8da6cb760972492ca3f1a273"
				},
			},
			{
				Field: "version",
				Type:  eip712.PrimitiveUint256,
				ValueFunc: func(_ Definition, _ Operator) any {
					return uint64(1)
				},
			},
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
		},
	}

	for _, field := range typ.Fields {
		data.Type.Fields = append(data.Type.Fields, eip712.Field{
			Name:  field.Field,
			Type:  field.Type,
			Value: field.ValueFunc(def, operator),
		})
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

// SignTermsAndConditions returns the EIP712 signature for Obol's Terms and Conditions
func SignTermsAndConditions(secret *k1.PrivateKey, def Definition) ([]byte, error) {
	return signEIP712(secret, eip712TermsAndConditions, def, Operator{})
}

// SignClusterDefinitionHash returns the EIP712 signature for cluster configuration hash
func SignClusterDefinitionHash(secret *k1.PrivateKey, def Definition) ([]byte, error) {
	return signEIP712(secret, eip712CreatorConfigHash, def, Operator{})
}
