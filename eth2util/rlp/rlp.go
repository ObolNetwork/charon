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
func EncodeBytesList(items [][]byte) []byte {
	var output []byte

	for _, item := range items {
		output = append(output, EncodeBytes(item)...)
	}

	return append(encodeLength(len(output), 0xc0), output...)
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
func EncodeBytes(item []byte) []byte {
	if len(item) == 1 && item[0] < 0x80 {
		return item
	}

	return append(encodeLength(len(item), 0x80), item...)
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
		if length > 64 {
			return 0, 0, errors.New("invalid length prefix")
		}

		return 1 + length, fromBigEndian(item, 1, length), nil
	}

	if prefix < 0xf8 {
		return 1, int(prefix - 0xc0), nil
	}

	length = int(prefix - 0xf7)
	if length > 64 {
		return 0, 0, errors.New("invalid length prefix")
	}

	return 1 + length, fromBigEndian(item, 1, length), nil
}

// encodeLength return the RLP encoding prefix for the given item length and offset.
func encodeLength(length, offset int) []byte {
	if length < 56 {
		return []byte{byte(length + offset)}
	}

	b := toBigEndian(length)

	prefix := len(b) + offset + 55

	return append([]byte{byte(prefix)}, b...)
}

// toBigEndian returns the big endian representation of the given integer without leading zeros.
func toBigEndian(i int) []byte {
	var resp []byte
	for i > 0 {
		resp = append([]byte{byte(i)}, resp...)
		i >>= 8
	}

	return resp
}

// fromBigEndian returns the integer encoded as big endian at the provided byte slice offset and length.
func fromBigEndian(b []byte, offset int, length int) int {
	var x uint64
	for i := offset; i < offset+length; i++ {
		x = x<<8 | uint64(b[i])
	}

	return int(x)
}
