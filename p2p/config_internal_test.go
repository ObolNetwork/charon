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

package p2p

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveListenAddr(t *testing.T) {
	tests := []struct {
		input string
		addr  net.IP
		port  int
		err   string
	}{
		{
			input: ":1234",
			err:   `p2p bind IP not specified`,
		},
		{
			input: "10.4.3.3:1234",
			addr:  net.IPv4(10, 4, 3, 3),
			port:  1234,
		},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			addr, err := resolveListenAddr(test.input)
			if test.err != "" {
				if err != nil {
					require.Error(t, err)
					require.Contains(t, err.Error(), test.err)
				} else {
					t.Errorf("Expected error but got %s for %s", addr.String(), test.input)
				}
			} else {
				require.Equal(t, test.addr, addr.IP)
				require.Equal(t, test.port, addr.Port)
			}
		})
	}
}

func TestConfig_Multiaddrs(t *testing.T) {
	c := Config{
		TCPAddrs: []string{
			"10.0.0.2:0",
			"[" + net.IPv6linklocalallnodes.String() + "]:0",
		},
	}

	maddrs, err := c.Multiaddrs()
	require.NoError(t, err)

	maddrStrs := make([]string, len(maddrs))
	for i, ma := range maddrs {
		maddrStrs[i] = ma.String()
	}

	require.Equal(t, []string{
		"/ip4/10.0.0.2/tcp/0",
		"/ip6/ff02::1/tcp/0",
	}, maddrStrs)
}
