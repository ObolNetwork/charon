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

package enr_test

import (
	"crypto/ecdsa"
	"fmt"
	"math/rand"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util/enr"
)

func TestParse(t *testing.T) {
	// Figure obtained from example cluster definition and public key verified with https://enr-viewer.com/.
	r, err := enr.Parse("enr:-Iu4QJyserRukhG0Vgi2csu7GjpHYUGufNEbZ8Q7ZBrcZUb0KqpL5QzHonkh1xxHlxatTxrIcX_IS5J3SEWR_sa0ptGAgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQMAUgEqczOjevyculnUIofhCj0DkgJudErM7qCYIvIkzIN0Y3CCDhqDdWRwgg4u")
	require.NoError(t, err)
	require.Equal(t,
		"0x030052012a7333a37afc9cba59d42287e10a3d0392026e744acceea09822f224cc",
		fmt.Sprintf("%#x", crypto.CompressPubkey(r.PubKey)),
	)
}

func TestEncodeDecode(t *testing.T) {
	privkey, err := ecdsa.GenerateKey(crypto.S256(), rand.New(rand.NewSource(0)))
	require.NoError(t, err)

	r1, err := enr.New(privkey)
	require.NoError(t, err)

	r2, err := enr.Parse(r1.String())
	require.NoError(t, err)

	require.Equal(t, r1, r2)
}

func TestNew(t *testing.T) {
	privkey, err := ecdsa.GenerateKey(crypto.S256(), rand.New(rand.NewSource(0)))
	require.NoError(t, err)

	r, err := enr.New(privkey)
	require.NoError(t, err)

	require.Equal(t, "enr:-HW4QMNo8q6cHeIVPW70BA6PZKjKwTKNIALmuE0tkvtAB8YgYzOYYaf8evsNo2Z1nnqPRiJAJp3-1i3shLchccqovCmAgmlkgnY0iXNlY3AyNTZrMaECvI5821Dg_9UqVPr5hNasj-XuaFbTil-KzZvTP8nH1Q0", r.String())
}
