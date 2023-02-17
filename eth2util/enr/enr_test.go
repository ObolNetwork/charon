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
	"fmt"
	"math/rand"
	"net"
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/testutil"
)

func TestParse(t *testing.T) {
	// Figure obtained from example cluster definition and public key verified with https://enr-viewer.com/.
	r, err := enr.Parse("enr:-Iu4QJyserRukhG0Vgi2csu7GjpHYUGufNEbZ8Q7ZBrcZUb0KqpL5QzHonkh1xxHlxatTxrIcX_IS5J3SEWR_sa0ptGAgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQMAUgEqczOjevyculnUIofhCj0DkgJudErM7qCYIvIkzIN0Y3CCDhqDdWRwgg4u")
	require.NoError(t, err)
	require.Equal(t,
		"0x030052012a7333a37afc9cba59d42287e10a3d0392026e744acceea09822f224cc",
		fmt.Sprintf("%#x", r.PubKey.SerializeCompressed()),
	)
	ip, ok := r.IP()
	require.True(t, ok)
	require.Equal(t, net.IPv4(127, 0, 0, 1).To4(), ip)

	tcp, ok := r.TCP()
	require.True(t, ok)
	require.Equal(t, 3610, tcp)

	udp, ok := r.UDP()
	require.True(t, ok)
	require.Equal(t, 3630, udp)
}

func TestEncodeDecode(t *testing.T) {
	privkey, err := k1.GeneratePrivateKey()
	require.NoError(t, err)

	r1, err := enr.New(privkey)
	require.NoError(t, err)

	r2, err := enr.Parse(r1.String())
	require.NoError(t, err)

	require.Equal(t, r1, r2)

	_, ok := r1.IP()
	require.False(t, ok)

	_, ok = r1.TCP()
	require.False(t, ok)
}

func TestIPTCP(t *testing.T) {
	privkey, err := k1.GeneratePrivateKey()
	require.NoError(t, err)

	expectIP := net.IPv4(1, 2, 3, 4)
	expectTCP := 8000
	expectUDP := 9000

	r1, err := enr.New(privkey, enr.WithIP(expectIP), enr.WithTCP(expectTCP), enr.WithUDP(expectUDP))
	require.NoError(t, err)

	ip, ok := r1.IP()
	require.True(t, ok)
	require.Equal(t, expectIP.To4(), ip)

	tcp, ok := r1.TCP()
	require.True(t, ok)
	require.Equal(t, expectTCP, tcp)

	udp, ok := r1.UDP()
	require.True(t, ok)
	require.Equal(t, expectUDP, udp)

	r2, err := enr.Parse(r1.String())
	require.NoError(t, err)

	ip, ok = r2.IP()
	require.True(t, ok)
	require.Equal(t, expectIP.To4(), ip)

	tcp, ok = r2.TCP()
	require.True(t, ok)
	require.Equal(t, expectTCP, tcp)

	udp, ok = r2.UDP()
	require.True(t, ok)
	require.Equal(t, expectUDP, udp)
}

func TestNew(t *testing.T) {
	privkey := testutil.GenerateInsecureK1Key(t, rand.New(rand.NewSource(0)))

	r, err := enr.New(privkey)
	require.NoError(t, err)

	require.Equal(t, "enr:-HW4QE_bilJiV518riilxqJ_693Fazktmp3RzesUnI_Afmj_X2XdHCiCl2wA_aIGZ6s09C4Xwlvy3XrpWgraDRpAlJWAgmlkgnY0iXNlY3AyNTZrMaECrpLOdVOZPwRADGl2-M1FQK4Ha_ATHuyLNa4P-fxXepA", r.String())
}
