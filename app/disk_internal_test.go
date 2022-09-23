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

package app

import (
	"crypto/ecdsa"
	"encoding/json"
	"math/rand"
	"os"
	"path"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
)

func TestLoadLock(t *testing.T) {
	lock, _, _ := cluster.NewForT(t, 1, 2, 3, 0)

	b, err := json.MarshalIndent(lock, "", " ")
	require.NoError(t, err)

	dir, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	filename := path.Join(dir, "cluster-lock.json")

	err = os.WriteFile(filename, b, 0o644)
	require.NoError(t, err)

	conf := Config{LockFile: filename}
	actual, err := loadLock(conf)
	require.NoError(t, err)

	b2, err := json.Marshal(actual)
	require.NoError(t, err)
	require.JSONEq(t, string(b), string(b2))
}

func TestVerifyP2PKey(t *testing.T) {
	lock, keys, _ := cluster.NewForT(t, 1, 3, 4, 0)

	for _, key := range keys {
		require.NoError(t, verifyP2PKey(lock, key))
	}

	key, err := ecdsa.GenerateKey(crypto.S256(), rand.New(rand.NewSource(time.Now().Unix())))
	require.NoError(t, err)
	require.Error(t, verifyP2PKey(lock, key))
}
