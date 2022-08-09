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

package deposit

import (
	"encoding/hex"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithdrawalCredentials(t *testing.T) {
	expectedWithdrawalCreds := "010000000000000000000000c0404ed740a69d11201f5ed297c5732f562c6e4e"
	creds, err := withdrawalCredsFromAddr("0xc0404ed740a69d11201f5ed297c5732f562c6e4e")
	require.NoError(t, err)

	credsHex := hex.EncodeToString(creds[:])

	require.Equal(t, expectedWithdrawalCreds, credsHex)
}

func TestNetworkToForkVersion(t *testing.T) {
	actual := networkToForkVersion("goerli")
	assert.EqualValues(t, eth2p0.Version([4]byte{0x00, 0x00, 0x10, 0x20}), actual)
}
