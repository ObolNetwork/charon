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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/combine"
	"github.com/obolnetwork/charon/eth2util/keystore"
	tblsv2 "github.com/obolnetwork/charon/tbls/v2"
)

func TestMain(m *testing.M) {
	tblsv2.SetImplementation(tblsv2.Herumi{})
	os.Exit(m.Run())
}

func TestCombineNoLockfile(t *testing.T) {
	td := t.TempDir()
	err := combine.Combine(context.Background(), td, false)
	require.ErrorContains(t, err, "read lock file")
}

func TestCombineMissingENR(t *testing.T) {
	lock, _, shares := cluster.NewForT(t, 2, 3, 4, 0)

	dir := t.TempDir()

	storeLock(t, dir, lock)

	// flatten secrets, each validator slice is unpacked in a flat structure
	var rawSecrets []tblsv2.PrivateKey
	for _, s := range shares {
		rawSecrets = append(rawSecrets, s...)
	}

	// for each ENR, create a slice of keys to hold
	// each set will be len(lock.Definition.Operators)
	secrets := make([][]tblsv2.PrivateKey, len(lock.Definition.Operators))

	// populate key sets
	for enrIdx := 0; enrIdx < len(lock.Definition.Operators); enrIdx++ {
		keyIdx := enrIdx
		for dvIdx := 0; dvIdx < lock.NumValidators; dvIdx++ {
			secrets[enrIdx] = append(secrets[enrIdx], rawSecrets[keyIdx])
			keyIdx += len(lock.Definition.Operators)
		}
	}

	for idx, keys := range secrets {
		if idx+1 == len(lock.Operators) {
			break
		}
		op := lock.Definition.Operators[idx]
		ep := filepath.Join(dir, op.ENR)

		require.NoError(t, os.Mkdir(ep, 0o755))
		require.NoError(t, keystore.StoreKeys(keys, ep))
	}

	err := combine.Combine(context.Background(), dir, false)
	require.ErrorContains(t, err, "enr path not found")
}

func TestCombineCannotLoadKeystore(t *testing.T) {
	lock, _, shares := cluster.NewForT(t, 2, 3, 4, 0)

	dir := t.TempDir()

	storeLock(t, dir, lock)

	// flatten secrets, each validator slice is unpacked in a flat structure
	var rawSecrets []tblsv2.PrivateKey
	for _, s := range shares {
		rawSecrets = append(rawSecrets, s...)
	}

	// for each ENR, create a slice of keys to hold
	// each set will be len(lock.Definition.Operators)
	secrets := make([][]tblsv2.PrivateKey, len(lock.Definition.Operators))

	// populate key sets
	for enrIdx := 0; enrIdx < len(lock.Definition.Operators); enrIdx++ {
		keyIdx := enrIdx
		for dvIdx := 0; dvIdx < lock.NumValidators; dvIdx++ {
			secrets[enrIdx] = append(secrets[enrIdx], rawSecrets[keyIdx])
			keyIdx += len(lock.Definition.Operators)
		}
	}

	for idx, keys := range secrets {
		op := lock.Definition.Operators[idx]
		ep := filepath.Join(dir, op.ENR)

		require.NoError(t, os.Mkdir(ep, 0o755))
		require.NoError(t, keystore.StoreKeys(keys, ep))
	}

	// delete one share off the first directory
	firstENR := lock.Definition.Operators[0]
	firstENRPath := filepath.Join(dir, firstENR.ENR)

	require.NoError(t, os.Remove(filepath.Join(firstENRPath, "keystore-0.json")))
	require.NoError(t, os.Remove(filepath.Join(firstENRPath, "keystore-1.json")))

	err := combine.Combine(context.Background(), dir, false)
	require.ErrorContains(t, err, "cannot load keystore")
}

func TestCombine(t *testing.T) {
	lock, _, shares := cluster.NewForT(t, 2, 3, 4, 0)

	// calculate expected public keys and secrets
	type expected struct {
		pubkey string
		secret string
	}

	var expectedData []expected

	for _, share := range shares {
		share := share

		sm := make(map[int]tblsv2.PrivateKey)
		for idx, shareObj := range share {
			shareObj := shareObj
			sm[idx+1] = shareObj
		}

		complSecret, err := tblsv2.RecoverSecret(sm, 4, 3)
		require.NoError(t, err)

		complPubkey, err := tblsv2.SecretToPublicKey(complSecret)
		require.NoError(t, err)

		expectedData = append(expectedData, expected{
			pubkey: fmt.Sprintf("%#x", complPubkey),
			secret: fmt.Sprintf("%#x", complSecret),
		})
	}

	dir := t.TempDir()

	storeLock(t, dir, lock)

	// flatten secrets, each validator slice is unpacked in a flat structure
	var rawSecrets []tblsv2.PrivateKey
	for _, s := range shares {
		rawSecrets = append(rawSecrets, s...)
	}

	// for each ENR, create a slice of keys to hold
	// each set will be len(lock.Definition.Operators)
	secrets := make([][]tblsv2.PrivateKey, len(lock.Definition.Operators))

	// populate key sets
	for enrIdx := 0; enrIdx < len(lock.Definition.Operators); enrIdx++ {
		keyIdx := enrIdx
		for dvIdx := 0; dvIdx < lock.NumValidators; dvIdx++ {
			secrets[enrIdx] = append(secrets[enrIdx], rawSecrets[keyIdx])
			keyIdx += len(lock.Definition.Operators)
		}
	}

	for idx, keys := range secrets {
		op := lock.Definition.Operators[idx]
		ep := filepath.Join(dir, op.ENR)

		require.NoError(t, os.Mkdir(ep, 0o755))
		require.NoError(t, keystore.StoreKeys(keys, ep))
	}

	err := combine.Combine(context.Background(), dir, false)
	require.NoError(t, err)

	for _, exp := range expectedData {
		secretPath := filepath.Join(dir, fmt.Sprintf("%s.privkey", exp.pubkey))
		fc, err := os.ReadFile(secretPath)
		require.NoError(t, err)

		require.Equal(t, exp.secret, fmt.Sprintf("%#x", fc))
	}
}

func storeLock(t *testing.T, dir string, lock cluster.Lock) {
	t.Helper()

	b, err := json.Marshal(lock)
	require.NoError(t, err)

	file := filepath.Join(dir, "cluster-lock.json")

	require.NoError(t, os.WriteFile(file, b, 0o755))
}
