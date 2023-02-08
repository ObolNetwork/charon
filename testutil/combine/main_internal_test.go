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

package main

import (
	"context"
	"encoding/json"
	"os"
	"path"
	"testing"

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	tblsv2 "github.com/obolnetwork/charon/tbls/v2"
)

func TestMain(m *testing.M) {
	tblsv2.SetImplementation(tblsv2.Herumi{})
	os.Exit(m.Run())
}

func TestCombine(t *testing.T) {
	lock, _, shares := cluster.NewForT(t, 1, 3, 4, 0)

	dir := t.TempDir()

	lockfile := storeLock(t, dir, lock)

	var secrets []*bls_sig.SecretKey
	for _, share := range shares[0] {
		secret, err := tblsconv.ShareToSecret(share)
		require.NoError(t, err)
		secrets = append(secrets, secret)
	}
	err := keystore.StoreKeys(secrets, dir)
	require.NoError(t, err)

	out := t.TempDir()

	err = run(context.Background(), lockfile, dir, out)
	require.NoError(t, err)

	result, err := keystore.LoadKeys(out)
	require.NoError(t, err)
	require.Len(t, result, 1)

	pubkey, err := result[0].GetPublicKey()
	require.NoError(t, err)
	actualBytes, err := pubkey.MarshalBinary()
	require.NoError(t, err)

	pubkey, err = lock.Validators[0].PublicKey()
	require.NoError(t, err)
	expectBytes, err := pubkey.MarshalBinary()
	require.NoError(t, err)

	require.Equal(t, expectBytes, actualBytes)
}

func storeLock(t *testing.T, dir string, lock cluster.Lock) string {
	t.Helper()

	b, err := json.Marshal(lock)
	require.NoError(t, err)

	file := path.Join(dir, "lock.json")

	err = os.WriteFile(file, b, 0o755)
	require.NoError(t, err)

	return file
}
