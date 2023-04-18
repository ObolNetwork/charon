// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

		if end > len(input) || start > end {
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
		length = int(prefix - 0xb7)    // length of the string in bytes in binary form
		if length > 8 || length <= 0 { // This is impossible based on outer if else checks
			panic("length not in expected range [1,8]")
		}

		offset := 1 + length

		resp, err := fromBigEndian(item, 1, length)
		if err != nil {
			return 0, 0, err
		} else if resp < 0 {
			return 0, 0, errors.New("negative length")
		} else if offset > offset+resp {
			return 0, 0, errors.New("overflow")
		}

		return offset, resp, nil
	}

	if prefix < 0xf8 {
		return 1, int(prefix - 0xc0), nil
	}

	length = int(prefix - 0xf7)
	if length > 8 || length <= 0 { // This is impossible based on outer if else checks
		panic("length not in expected range [1,8]")
	}

	offset = 1 + length

	resp, err := fromBigEndian(item, 1, length)
	if err != nil {
		return 0, 0, err
	} else if resp < 0 {
		return 0, 0, errors.New("negative length")
	} else if offset > offset+resp {
		return 0, 0, errors.New("overflow")
	}

	return offset, resp, nil
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
func fromBigEndian(b []byte, offset int, length int) (int, error) {
	if offset >= len(b) || offset+length >= len(b) {
		return 0, errors.New("input too short")
	}

	var x uint64
	for i := offset; i < offset+length; i++ {
		x = x<<8 | uint64(b[i])
	}

	return int(x), nil
}
