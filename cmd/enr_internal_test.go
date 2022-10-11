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
	"io"
	"math/rand"
	"net"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestRunNewEnr(t *testing.T) {
	temp, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	got := runNewENR(io.Discard, p2p.Config{}, temp, false)
	expected := errors.New("private key not found. If this is your first time running this client, create one with `charon create enr`.", z.Str("enr_path", p2p.KeyPath(temp)))
	require.Equal(t, expected.Error(), got.Error())
}

func TestEnrNetworkingKeys(t *testing.T) {
	var (
		r        enr.Record
		ip       = enr.IPv4(net.ParseIP("192.168.3.45"))
		ip6      = enr.IPv6(net.ParseIP("192.123.87.12"))
		tcp      = enr.TCP(4987)
		tcp6     = enr.TCP6(9844)
		udp      = enr.UDP(1344)
		udp6     = enr.UDP6(5198)
		expected = "ip: 192.168.3.45\nip6: 192.123.87.12\ntcp: 4987\ntcp6: 9844\nudp: 1344\nudp6: 5198\n"
	)

	_, r = testutil.RandomENR(t, rand.New(rand.NewSource(time.Now().Unix())))

	r.Set(ip)
	r.Set(ip6)
	r.Set(tcp)
	r.Set(tcp6)
	r.Set(udp)
	r.Set(udp6)

	got := enrNetworkingKeys(r)
	require.Equal(t, expected, got)
}
