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

package cmd

import (
	"crypto/ecdsa"
	"encoding/hex"
	"io"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/p2p"
)

const (
	compressedK1PubkeyLen = 33
)

func TestRunNewEnr(t *testing.T) {
	temp, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	got := runNewENR(io.Discard, temp, false)
	expected := errors.New("private key not found. If this is your first time running this client, create one with `charon create enr`.", z.Str("enr_path", p2p.KeyPath(temp)))
	require.Equal(t, expected.Error(), got.Error())
}

func TestPubkeyHex(t *testing.T) {
	key, err := ecdsa.GenerateKey(crypto.S256(), rand.New(rand.NewSource(time.Now().Unix())))
	require.NoError(t, err)

	pk := pubkeyHex(key.PublicKey)
	bytes, err := hex.DecodeString(strings.TrimPrefix(pk, "0x"))
	require.NoError(t, err)
	require.Equal(t, len(bytes), compressedK1PubkeyLen)
}
