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

package rlp_test

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util/rlp"
	"github.com/obolnetwork/charon/testutil"
)

// TestBytes tests encoding and decoding of byte slices using examples from the RLP spec.
// See https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/#examples.
func TestBytes(t *testing.T) {
	tests := []struct {
		input  []byte
		output []byte
	}{
		{
			input:  []byte("dog"),
			output: []byte{0x83, byte('d'), byte('o'), byte('g')},
		},
		{
			input:  []byte(""),
			output: []byte{0x80},
		},
		{
			input:  nil,
			output: []byte{0x80},
		},
		// Not sure how to represent "the integer 0" resulting in "[]byte{0x80}"
		{
			input:  []byte{0x00},
			output: []byte{0x00},
		},
		{
			input:  []byte{0x0f},
			output: []byte{0x0f},
		},
		{
			input:  []byte("Lorem ipsum dolor sit amet, consectetur adipisicing elit"),
			output: []byte{0xb8, 0x38, 'L', 'o', 'r', 'e', 'm', ' ', 'i', 'p', 's', 'u', 'm', ' ', 'd', 'o', 'l', 'o', 'r', ' ', 's', 'i', 't', ' ', 'a', 'm', 'e', 't', ',', ' ', 'c', 'o', 'n', 's', 'e', 'c', 't', 'e', 't', 'u', 'r', ' ', 'a', 'd', 'i', 'p', 'i', 's', 'i', 'c', 'i', 'n', 'g', ' ', 'e', 'l', 'i', 't'},
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			encoded, err := rlp.EncodeBytes(test.input)
			testutil.RequireNoError(t, err)
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
			rand.Read(buf)

			encoded, err := rlp.EncodeBytes(buf)
			if len(buf) >= 1024 {
				require.ErrorContains(t, err, "input too long")
				return
			}
			testutil.RequireNoError(t, err)

			decoded, err := rlp.DecodeBytes(encoded)
			testutil.RequireNoError(t, err)

			require.Equal(t, buf, decoded)
		})
	}
}
