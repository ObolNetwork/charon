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
	"bytes"
	"encoding/base64"
	"math/rand"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestDecodeENR(t *testing.T) {
	lock, _, _ := cluster.NewForT(t, 1, 3, 4, 0)

	for _, o := range lock.Operators {
		record, err := p2p.DecodeENR(o.ENR)
		require.NoError(t, err)

		enrStr, err := p2p.EncodeENR(record)
		require.NoError(t, err)

		require.Equal(t, o.ENR, enrStr)
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
	_, err := p2p.DecodeENR("enr:-IS4QBnEa-Oftjk7-sGRAY7IrvL5YjATdcHbqR5l2aXX2M25CiawfwaXh0k9hm98dCfdnqhz9mE-BfemFdjuL9KtHqgBgmlkgnY0gmlwhB72zxGJc2VjcDI1NmsxoQMaK8SspTrUgB8IYVI3qDgFYsHymPVsWlvIW477kxaKUIN0Y3CCJpUAAAA")
	require.Error(t, err)
	require.Contains(t, err.Error(), "input contains more than one value")
}

func TestBackwardsENR(t *testing.T) {
	random := rand.New(rand.NewSource(time.Now().Unix()))
	for i := 0; i < 100; i++ {
		_, record := testutil.RandomENR(t, random)
		enrStr := encodeOldVersion(t, record)

		_, err := p2p.DecodeENR(enrStr)
		require.NoError(t, err)
	}
}

// encodeOldVersion returns encoded ENR string with padding which is supported by v0.9.0 or earlier.
func encodeOldVersion(t *testing.T, r enr.Record) string {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, r.EncodeRLP(&buf))

	return "enr:" + base64.URLEncoding.EncodeToString(buf.Bytes())
}
