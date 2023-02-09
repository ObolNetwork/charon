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

package enr

import (
	"crypto/ecdsa"
	"encoding/base64"
	"math/rand"
	"testing"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

func TestBackwardsENR(t *testing.T) {
	random := rand.New(rand.NewSource(time.Now().Unix()))
	for i := 0; i < 100; i++ {
		k, err := ecdsa.GenerateKey(k1.S256(), random)
		require.NoError(t, err)

		key := k1.PrivKeyFromBytes(k.D.Bytes())

		record, err := New(key)
		require.NoError(t, err)

		// Encode ENR string with padding which is supported by charon versions v0.9.0 or earlier.
		enrStr := "enr:" + base64.URLEncoding.EncodeToString(encodeElements(record.Signature, record.kvs))

		_, err = Parse(enrStr)
		require.NoError(t, err)
	}
}
