// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package p2p

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
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
					assert.Error(t, err)
					assert.Contains(t, err.Error(), test.err)
				} else {
					t.Errorf("Expected error but got %s for %s", addr.String(), test.input)
				}
			} else {
				assert.Equal(t, test.addr, addr.IP)
				assert.Equal(t, test.port, addr.Port)
			}
		})
	}
}

func TestConfig_Multiaddrs(t *testing.T) {
	c := Config{
		Addrs: []string{
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
