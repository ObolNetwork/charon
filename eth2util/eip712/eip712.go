// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package eip712 provides a minimal EIP-712 implementation supporting only a few
// primitive types and fixed set of domain fields. See https://eips.ethereum.org/EIPS/eip-712.
package eip712

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/sha3"

	"github.com/obolnetwork/charon/app/errors"
)

// Primitive represents a primitive field type.
type Primitive string

const (
	PrimitiveString  Primitive = "string"
	PrimitiveUint256 Primitive = "uint256"
)

// TypedData represents a dynamically typed EIP-712 message.
type TypedData struct {
	// Domain is the domain.
	Domain Domain
	// Type is the primary data-type.
	Type Type
}

// Type represents the primary data-type of an EIP-712 message.
type Type struct {
	Name   string
	Fields []Field
}

// Field is the field of an EIP-712 message primary data-type.
type Field struct {
	Name  string
	Type  Primitive
	Value any
}

// Domain represents the domain value of an EIP-712 message.
type Domain struct {
	Name    string
	Version string
	ChainID uint64
}

// domainToType returns the domain as an abstract type.
func domainToType(domain Domain) Type {
	return Type{
		Name: "EIP712Domain",
		Fields: []Field{
			{Name: "name", Type: PrimitiveString, Value: domain.Name},
			{Name: "version", Type: PrimitiveString, Value: domain.Version},
			{Name: "chainId", Type: PrimitiveUint256, Value: domain.ChainID},
		},
	}
}

// HashTypedData returns the hash of the typed data.
func HashTypedData(data TypedData) ([]byte, error) {
	domainHash, err := hashData(domainToType(data.Domain))
	if err != nil {
		return nil, err
	}
	dataHash, err := hashData(data.Type)
	if err != nil {
		return nil, err
	}
	rawData := fmt.Sprintf("\x19\x01%s%s", string(domainHash), string(dataHash))

	return keccakHash([]byte(rawData)), nil
}

// hashData returns the hash of the primary data type and value.
func hashData(typ Type) ([]byte, error) {
	var buf bytes.Buffer
	_, _ = buf.Write(hashType(typ))
	for _, field := range typ.Fields {
		b, err := encodeField(field)
		if err != nil {
			return nil, errors.Wrap(err, "encode field")
		}
		_, _ = buf.Write(b)
	}

	return keccakHash(buf.Bytes()), nil
}

// encodeField returns the encoded primitive field.
func encodeField(field Field) ([]byte, error) {
	switch field.Type {
	case PrimitiveString:
		s, ok := field.Value.(string)
		if !ok {
			return nil, errors.New("invalid string field")
		}

		return keccakHash([]byte(s)), nil
	case PrimitiveUint256:
		i, ok := field.Value.(uint64)
		if !ok {
			return nil, errors.New("invalid uint64 field")
		}

		b := make([]byte, 32)
		binary.BigEndian.PutUint64(b[24:], i) // Encode int64 as last 8 bytes 32-8=24.

		return b, nil

	default:
		return nil, errors.New("unsupported field type")
	}
}

// hashType returns the hash of the encoded type.
func hashType(typ Type) []byte {
	return keccakHash(encodeType(typ))
}

// encodeType return the following encoding:
// `{.Name}({.Fields[0].Type} {.Fields[0].Name},{.Fields[1].Type} {.Fields[1].Name},...)`.
func encodeType(typ Type) []byte {
	var buf bytes.Buffer
	_, _ = buf.WriteString(typ.Name)
	_, _ = buf.WriteString("(")
	for i, field := range typ.Fields {
		if i != 0 {
			_, _ = buf.WriteString(",")
		}
		_, _ = buf.WriteString(string(field.Type))
		_, _ = buf.WriteString(" ")
		_, _ = buf.WriteString(field.Name)
	}
	_, _ = buf.WriteString(")")

	return buf.Bytes()
}

// keccakHash returns the keccak256 hash of the data.
func keccakHash(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write(data)

	return h.Sum(nil)
}
