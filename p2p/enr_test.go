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

package p2p_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/p2p"
)

func TestDecodeENR(t *testing.T) {
	manifest, _, _ := app.NewClusterForT(t, 1, 3, 4, 0)

	for _, p := range manifest.Peers {
		enrStr, err := p2p.EncodeENR(p.ENR)
		require.NoError(t, err)

		record2, err := p2p.DecodeENR(enrStr)
		require.NoError(t, err)
		require.Equal(t, p.ENR, record2)
	}
}

func TestDecodeENR_InvalidBase64(t *testing.T) {
	_, err := p2p.DecodeENR("enr:###")
	require.Error(t, err)
	require.Contains(t, err.Error(), "illegal base64 data at input byte 0")
}

func TestDecodeENR_InvalidRLP(t *testing.T) {
	_, err := p2p.DecodeENR("enr:AAAAAAAA")
	require.Error(t, err)
	require.Contains(t, err.Error(), "rlp: expected List")
}

func TestDecodeENR_Oversize(t *testing.T) {
	_, err := p2p.DecodeENR("enr:-IS4QBnEa-Oftjk7-sGRAY7IrvL5YjATdcHbqR5l2aXX2M25CiawfwaXh0k9hm98dCfdnqhz9mE-BfemFdjuL9KtHqgBgmlkgnY0gmlwhB72zxGJc2VjcDI1NmsxoQMaK8SspTrUgB8IYVI3qDgFYsHymPVsWlvIW477kxaKUIN0Y3CCJpUAAAA=")
	require.Error(t, err)
	require.Contains(t, err.Error(), "input contains more than one value")
}
