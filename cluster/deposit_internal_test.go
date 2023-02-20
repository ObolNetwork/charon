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

package cluster

import (
	"encoding/json"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"
)

func TestDepositJSON(t *testing.T) {
	deposit := RandomDepositData()
	depositJSON := depositDataToJSON(deposit)

	eth2Deposit := &eth2p0.DepositData{
		PublicKey:             *(*eth2p0.BLSPubKey)(deposit.PubKey),
		WithdrawalCredentials: deposit.WithdrawalCredentials,
		Amount:                eth2p0.Gwei(deposit.Amount),
		Signature:             *(*eth2p0.BLSSignature)(deposit.Signature),
	}

	b1, err := json.MarshalIndent(depositJSON, "", " ")
	require.NoError(t, err)
	b2, err := json.MarshalIndent(eth2Deposit, "", " ")
	require.NoError(t, err)

	require.Equal(t, b1, b2)
}
