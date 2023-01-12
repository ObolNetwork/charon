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

// Package rlp implements the simple byte slice and lists of byte slices encoding/decoding using
// recursive length prefix encoding scheme as per spec
// https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/.
package rlp

import (
	"encoding/binary"

	"github.com/obolnetwork/charon/app/errors"
)

// DecodeBytesList returns the list of byte slices contained in the given RLP encoded byte slice.
func DecodeBytesList(input []byte) ([][]byte, error) {
	if len(input) == 0 {
		return nil, nil
	}

	offset, length, err := decodeLength(input)
	if err != nil {
		return nil, err
	}

	if offset+length > len(input) {
		return nil, errors.New("input too short")
	}

	var items [][]byte
	for i := offset; i < offset+length; {
		itemOffset, itemLength, err := decodeLength(input[i:])
		if err != nil {
			return nil, err
		}

		start := i + itemOffset
		end := i + itemOffset + itemLength

		if end > len(input) {
			return nil, errors.New("input too short")
		}

		items = append(items, input[start:end])

		i = end
	}

	return items, nil
}

// EncodeBytesList returns a byte slice containing the RLP encoding of the given list of byte slices.
func EncodeBytesList(items [][]byte) ([]byte, error) {
	var output []byte

	for _, item := range items {
		b, err := EncodeBytes(item)
		if err != nil {
			return nil, err
		}

		output = append(output, b...)
	}

	length, err := encodeLength(len(output), 0xc0)
	if err != nil {
		return nil, err
	}

	return append(length, output...), nil
}

// DecodeBytes returns the byte slices contained in the given RLP encoded byte slice.
func DecodeBytes(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, nil
	}

	offset, length, err := decodeLength(input)
	if err != nil {
		return nil, err
	}

	if offset+length > len(input) {
		return nil, errors.New("input too short")
	}

	return input[offset : offset+length], nil
}

// EncodeBytes returns a byte slice containing the RLP encoding of the given byte slice.
func EncodeBytes(item []byte) ([]byte, error) {
	if len(item) == 1 && item[0] < 0x80 {
		return item, nil
	}

	length, err := encodeLength(len(item), 0x80)
	if err != nil {
		return nil, err
	}

	return append(length, item...), nil
}

// decodeLength returns the length of the RLP encoding prefix (offset) and the length of the encoded byte slice.
func decodeLength(item []byte) (offset int, length int, err error) {
	if len(item) == 0 {
		return 0, 0, errors.New("input too short")
	}

	prefix := item[0]

	if prefix < 0x80 {
		return 0, 1, nil
	}

	if prefix < 0xb8 {
		return 1, int(prefix - 0x80), nil
	}

	if prefix < 0xc0 {
		length = int(prefix - 0xb7)
		if length > 8 {
			return 0, 0, errors.New("invalid length prefix")
		}
		if len(item) < length+1 {
			return 0, 0, errors.New("input too short")
		}

		// Prepend leading zero to make length 8 bytes long.
		lengthAsBytes := make([]byte, 8)
		copy(lengthAsBytes[8-length:], item[1:length+1])

		return 1 + length, int(binary.BigEndian.Uint64(lengthAsBytes)), nil
	}

	if prefix < 0xf8 {
		return 1, int(prefix - 0xc0), nil
	}

	length = int(prefix - 0xf7)
	if length > 8 {
		return 0, 0, errors.New("invalid length prefix")
	}
	if len(item) < length+1 {
		return 0, 0, errors.New("input too short")
	}

	// Prepend leading zero to make length 8 bytes long.
	lengthAsBytes := make([]byte, 8)
	copy(lengthAsBytes[8-length:], item[1:length+1])

	return 1 + length, int(binary.BigEndian.Uint64(lengthAsBytes)), nil
}

// encodeLength return the RLP encoding prefix for the given item length and offset.
func encodeLength(length, offset int) ([]byte, error) {
	if length >= 1024 {
		return nil, errors.New("input too long")
	}

	if length < 56 {
		return []byte{byte(length + offset)}, nil
	}

	lengthAsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(lengthAsBytes, uint64(length))

	// Remove leading zeros.
	for i := 0; i < len(lengthAsBytes); i++ {
		if lengthAsBytes[i] != 0 {
			lengthAsBytes = lengthAsBytes[i:]
			break
		}
	}

	prefix := len(lengthAsBytes) + offset + 55

	return append([]byte{byte(prefix)}, lengthAsBytes...), nil
}
