// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
			addr, err := resolveListenTCPAddr(test.input)
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
		UDPAddrs: []string{
			"10.0.0.2:0",
			"[" + net.IPv6linklocalallnodes.String() + "]:0",
		},
	}

	tcpMaddrs, err := c.TCPMultiaddrs()
	require.NoError(t, err)

	udpMaddrs, err := c.UDPMultiaddrs()
	require.NoError(t, err)

	maddrStrs := make([]string, (len(tcpMaddrs) + len(udpMaddrs)))
	for i, ma := range tcpMaddrs {
		maddrStrs[i] = ma.String()
	}
	for i, ma := range udpMaddrs {
		maddrStrs[i+len(tcpMaddrs)] = ma.String()
	}

	require.Equal(t, []string{
		"/ip4/10.0.0.2/tcp/0",
		"/ip6/ff02::1/tcp/0",
		"/ip4/10.0.0.2/udp/0/quic-v1",
		"/ip6/ff02::1/udp/0/quic-v1",
	}, maddrStrs)
}
