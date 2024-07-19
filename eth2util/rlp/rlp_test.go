// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package rlp_test

import (
	"crypto/rand"
	"fmt"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util/rlp"
	"github.com/obolnetwork/charon/testutil"
)

var (
	loremIn  = []byte("Lorem ipsum dolor sit amet, consectetur adipisicing elit")
	loremOut = []byte{0xb8, 0x38, 'L', 'o', 'r', 'e', 'm', ' ', 'i', 'p', 's', 'u', 'm', ' ', 'd', 'o', 'l', 'o', 'r', ' ', 's', 'i', 't', ' ', 'a', 'm', 'e', 't', ',', ' ', 'c', 'o', 'n', 's', 'e', 'c', 't', 'e', 't', 'u', 'r', ' ', 'a', 'd', 'i', 'p', 'i', 's', 'i', 'c', 'i', 'n', 'g', ' ', 'e', 'l', 'i', 't'}
)

const (
	minPrefixSize  = 1
	minPayloadSize = 0
)

func FuzzDecodeBytesList(f *testing.F) {
	prefix := make([]byte, minPrefixSize)
	data := make([]byte, minPayloadSize)

	f.Add(merge(prefix, data))
	f.Fuzz(func(t *testing.T, d []byte) {
		_, err := rlp.DecodeBytesList(d)
		if err != nil {
			// only care about panics
			return
		}
	})
}

func FuzzDecodeBytes(f *testing.F) {
	prefix := make([]byte, minPrefixSize)
	data := make([]byte, minPayloadSize)

	f.Add(merge(prefix, data))
	f.Fuzz(func(t *testing.T, d []byte) {
		_, err := rlp.DecodeBytes(d)
		if err != nil {
			// only care about panics
			return
		}
	})
}

func FuzzEncodeBytesList(f *testing.F) {
	prefix := make([]byte, minPrefixSize)
	data := make([]byte, minPayloadSize)
	d := merge(prefix, data)

	// Add a few different lengths of byte slices
	for i := range 10 {
		f.Add(i, d, d, d, d, d, d, d, d, d, d)
	}

	f.Fuzz(func(t *testing.T, n int, d0, d1, d2, d3, d4, d5, d6, d7, d8, d9 []byte) {
		a := [][]byte{d0, d1, d2, d3, d4, d5, d6, d7, d8, d9}
		if n >= 0 && n < len(a) {
			a = a[:n]
		}

		rlp.EncodeBytesList(a)
	})
}

func FuzzEncodeBytes(f *testing.F) {
	prefix := make([]byte, minPrefixSize)
	data := make([]byte, minPayloadSize)

	f.Add(merge(prefix, data))
	f.Fuzz(func(t *testing.T, d []byte) {
		rlp.EncodeBytes(d)
	})
}

// TestBytesList tests encoding and decoding of lists of byte slices using examples from the RLP spec.
// See https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/#examples.
func TestBytesList(t *testing.T) {
	tests := []struct {
		input  [][]byte
		output []byte
	}{
		{
			input:  [][]byte{[]byte("cat"), []byte("dog")},
			output: []byte{0xc8, 0x83, 'c', 'a', 't', 0x83, 'd', 'o', 'g'},
		},
		{
			input:  [][]byte{},
			output: []byte{0xc0},
		},
		{
			input:  [][]byte{loremIn, loremIn, loremIn, loremIn, loremIn, loremIn, loremIn, loremIn},
			output: appendSlices([]byte{0xf9, 0x01, 0xd0}, loremOut, loremOut, loremOut, loremOut, loremOut, loremOut, loremOut, loremOut),
		},
	}
	for i, test := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			encoded := rlp.EncodeBytesList(test.input)
			if len(test.output) == 0 {
				require.Empty(t, encoded)
			} else {
				require.Equal(t, test.output, encoded)
			}

			decoded, err := rlp.DecodeBytesList(encoded)
			testutil.RequireNoError(t, err)
			if len(test.input) == 0 {
				require.Empty(t, decoded)
			} else {
				require.Equal(t, test.input, decoded)
			}
		})
	}
}

func merge(a, b []byte) []byte {
	resp := make([]byte, len(a)+len(b))
	copy(resp, a)
	copy(resp[len(a):], b)

	return resp
}

// TestBytes tests encoding and decoding of byte slices using examples from the RLP spec.
// See https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/#examples.
func TestBytes(t *testing.T) {
	tests := []struct {
		input  []byte
		output []byte
	}{
		{
			input:  []byte("dog"),
			output: []byte{0x83, 'd', 'o', 'g'},
		},
		{
			input:  []byte(""),
			output: []byte{0x80},
		},
		{
			input:  nil,
			output: []byte{0x80},
		},
		{
			input:  []byte{0x00},
			output: []byte{0x00},
		},
		{
			input:  []byte{0x0f},
			output: []byte{0x0f},
		},
		{
			input:  loremIn,
			output: loremOut,
		},
	}
	for i, test := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			encoded := rlp.EncodeBytes(test.input)
			if len(test.output) == 0 {
				require.Empty(t, encoded)
			} else {
				require.Equal(t, test.output, encoded)
			}

			decoded, err := rlp.DecodeBytes(encoded)
			testutil.RequireNoError(t, err)
			if len(test.input) == 0 {
				require.Empty(t, decoded)
			} else {
				require.Equal(t, test.input, decoded)
			}
		})
	}
}

func TestLengths(t *testing.T) {
	for _, length := range []int{0, 1, 55, 56, 1023, 1024} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			buf := make([]byte, length)
			_, err := rand.Read(buf)
			require.NoError(t, err)

			encoded := rlp.EncodeBytes(buf)

			decoded, err := rlp.DecodeBytes(encoded)
			testutil.RequireNoError(t, err)

			require.Equal(t, buf, decoded)
		})
	}
}

func appendSlices(slices ...[]byte) []byte {
	var resp []byte
	for _, slice := range slices {
		resp = append(resp, slice...)
	}

	return resp
}
