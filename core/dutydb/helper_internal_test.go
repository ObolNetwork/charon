// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dutydb

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestToAggBitsHex(t *testing.T) {
	tests := []struct {
		Length, Index uint64
		Output        string
	}{
		{
			Length: 8,
			Index:  0,
			Output: "0x01",
		},
		{
			Length: 0,
			Index:  0,
			Output: "0x00",
		},
		{
			Length: 2,
			Index:  1,
			Output: "0x02",
		},
		{
			Length: 8,
			Index:  7,
			Output: "0x80",
		},
		{
			Length: 256,
			Index:  1,
			Output: "0x0000000000000000000000000000000000000000000000000000000000000002",
		},
		{
			Length: 256,
			Index:  127,
			Output: "0x0000000000000000000000000000000080000000000000000000000000000000",
		},
		{
			Length: 256,
			Index:  128,
			Output: "0x0000000000000000000000000000000100000000000000000000000000000000",
		},
		{
			Length: 256,
			Index:  129,
			Output: "0x0000000000000000000000000000000200000000000000000000000000000000",
		},
	}
	for _, test := range tests {
		t.Run(test.Output, func(t *testing.T) {
			actual, err := getAggBitsHex(test.Length, test.Index)
			require.NoError(t, err)
			require.Equal(t, test.Output, actual)
		})
	}
}
