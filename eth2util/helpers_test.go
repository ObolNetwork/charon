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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util"
)

func TestChecksummedAddress(t *testing.T) {
	// Test examples from https://eips.ethereum.org/EIPS/eip-55.
	addrs := []string{
		"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
		"0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
		"0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
		"0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
	}
	for _, addr := range addrs {
		t.Run(addr, func(t *testing.T) {
			checksummed, err := eth2util.ChecksumAddress(addr)
			require.NoError(t, err)
			require.Equal(t, addr, checksummed)

			checksummed, err = eth2util.ChecksumAddress(strings.ToLower(addr))
			require.NoError(t, err)
			require.Equal(t, addr, checksummed)

			checksummed, err = eth2util.ChecksumAddress("0x" + strings.ToUpper(addr[2:]))
			require.NoError(t, err)
			require.Equal(t, addr, checksummed)
		})
	}
}

func TestInvalidAddrs(t *testing.T) {
	addrs := []string{
		"0x0000000000000000000000000000000000dead",
		"0x00000000000000000000000000000000000000dead",
		"0x0000000000000000000000000000000000000bar",
		"000000000000000000000000000000000000dead",
	}
	for _, addr := range addrs {
		t.Run(addr, func(t *testing.T) {
			_, err := eth2util.ChecksumAddress(addr)
			require.Error(t, err)
		})
	}
}
