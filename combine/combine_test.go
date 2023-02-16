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

package combine_test

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	tblsv2 "github.com/obolnetwork/charon/tbls/v2"
)

func TestMain(m *testing.M) {
	tblsv2.SetImplementation(tblsv2.Herumi{})
	os.Exit(m.Run())
}

// func TestCombineExistingOutdir(t *testing.T) {
//	lock, _, shares := cluster.NewForT(t, 1, 3, 4, 0)
//
//	dir := t.TempDir()
//
//	lockfile := storeLock(t, dir, lock)
//
//	secrets := shares[0]
//
//	err := keystore.StoreKeys(secrets, dir)
//	require.NoError(t, err)
//
//	out := t.TempDir()
//
//	err = combine.Combine(context.Background(), lockfile, dir, out)
//	require.NoError(t, err)
//
//	result, err := keystore.LoadKeys(out)
//	require.NoError(t, err)
//	require.Len(t, result, 1)
//
//	actualBytes, err := tblsv2.SecretToPublicKey(result[0])
//	require.NoError(t, err)
//
//	pubkey := lock.Validators[0].PubKey
//
//	require.Equal(t, pubkey, actualBytes[:])
//}

func TestCombine2(t *testing.T) {
	// lock, _, shares := cluster.NewForT(t, 2, 3, 4, 0)
	//
	//// TODO: split shares among ENRs
	//
	//dir := t.TempDir()
	//
	//storeLock(t, dir, lock)

	for i := 0; i < 4*2; i += 4 {
		log.Printf("for enr %d, grabbing keys [%d: %d]\n", i, i, i+2)
	}

	//// flatten secrets, each validator slice is unpacked in a flat structure
	//// there are now n*validator txt/json files
	// var secrets []tblsv2.PrivateKey
	//for _, s := range shares {
	//	secrets = append(secrets, s...)
	//}
	//
	//// temporarily store shares in a dir
	//tempSharesDir := t.TempDir()
	//err := keystore.StoreKeys(secrets, tempSharesDir)
	//require.NoError(t, err)
	//
	//for idx, dv := range lock.Definition.Operators {
	//	ep := filepath.Join(dir, dv.ENR)
	//
	//	require.NoError(t, os.Mkdir(ep, 0755))
	//}


	//require.NoError(t, err)

	// secrets := shares[0]
	//
	//err := keystore.StoreKeys(secrets, dir)
	//require.NoError(t, err)
	//
	//out := t.TempDir()
	//
	//err = combine.Combine(context.Background(), lockfile, dir, out)
	//require.NoError(t, err)
	//
	//result, err := keystore.LoadKeys(out)
	//require.NoError(t, err)
	//require.Len(t, result, 1)
	//
	//actualBytes, err := tblsv2.SecretToPublicKey(result[0])
	//require.NoError(t, err)
	//
	//pubkey := lock.Validators[0].PubKey
	//
	//require.Equal(t, pubkey, actualBytes[:])
}

func storeLock(t *testing.T, dir string, lock cluster.Lock) {
	t.Helper()

	b, err := json.Marshal(lock)
	require.NoError(t, err)

	file := filepath.Join(dir, "cluster-lock.json")

	require.NoError(t, os.WriteFile(file, b, 0o755))
}
