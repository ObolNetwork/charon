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

package eth2util_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util"
)

func TestSlotHashRoot(t *testing.T) {
	resp, err := eth2util.SlotHashRoot(2)
	require.NoError(t, err)
	require.Equal(t,
		"0200000000000000000000000000000000000000000000000000000000000000",
		hex.EncodeToString(resp[:]),
	)
}

func TestHash(t *testing.T) {
	hashOf0 := [32]byte{110, 52, 11, 156, 255, 179, 122, 152, 156, 165, 68, 230, 187, 120, 10, 44, 120, 144, 29, 63, 179, 55, 56, 118, 133, 17, 163, 6, 23, 175, 160, 29}
	h := eth2util.SHA256([]byte{0})
	require.Equal(t, hashOf0, h)

	hashOf1 := [32]byte{75, 245, 18, 47, 52, 69, 84, 197, 59, 222, 46, 187, 140, 210, 183, 227, 209, 96, 10, 214, 49, 195, 133, 165, 215, 204, 226, 60, 119, 133, 69, 154}
	h = eth2util.SHA256([]byte{1})
	require.Equal(t, hashOf1, h)
}
