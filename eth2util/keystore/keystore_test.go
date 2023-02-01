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

package keystore_test

import (
	"fmt"
	"testing"

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls"
)

func TestStoreLoad(t *testing.T) {
	dir := t.TempDir()

	var secrets []*bls_sig.SecretKey
	for i := 0; i < 2; i++ {
		_, secret, err := tbls.Keygen()
		require.NoError(t, err)

		secrets = append(secrets, secret)
	}

	err := keystore.StoreKeys(secrets, dir)
	require.NoError(t, err)

	actual, err := keystore.LoadKeys(dir)
	require.NoError(t, err)

	require.Equal(t, secrets, actual)
}

func TestLoadEmpty(t *testing.T) {
	_, err := keystore.LoadKeys(".")
	require.Error(t, err)
}

func TestLoadScrypt(t *testing.T) {
	secrets, err := keystore.LoadKeys("testdata")
	require.NoError(t, err)

	require.Len(t, secrets, 1)

	b, err := secrets[0].MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, "10b16fc552aa607fa1399027f7b86ab789077e470b5653b338693dc2dde02468", fmt.Sprintf("%x", b))
}
