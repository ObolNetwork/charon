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
	Type  string
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
			{Name: "name", Type: "string", Value: domain.Name},
			{Name: "version", Type: "string", Value: domain.Version},
			{Name: "chainId", Type: "uint256", Value: domain.ChainID},
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

func encodeField(field Field) ([]byte, error) {
	switch field.Type {
	case "string":
		s, ok := field.Value.(string)
		if !ok {
			return nil, errors.New("invalid string field")
		}

		return keccakHash([]byte(s)), nil
	case "uint256":
		i, ok := field.Value.(uint64)
		if !ok {
			return nil, errors.New("invalid uint64 field")
		}

		b := make([]byte, 32)
		binary.BigEndian.PutUint64(b[24:], i)

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
		_, _ = buf.WriteString(field.Type)
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
