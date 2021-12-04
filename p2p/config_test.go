package p2p

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveListenAddr(t *testing.T) {
	type testCase struct {
		str  string
		addr net.IP
		port int
		err  string
	}
	cases := []testCase{
		{
			str: ":1234",
			err: `IP not specified in P2P bind addr: ":1234"`,
		},
		{
			str: "0.0.0.0:1234",
			err: `IP not specified in P2P bind addr: "0.0.0.0:1234"`,
		},
		{
			str:  "10.4.3.3:1234",
			addr: net.IPv4(10, 4, 3, 3),
			port: 1234,
		},
	}
	for _, c := range cases {
		addr, port, err := resolveListenAddr(c.str)
		if len(c.err) > 0 {
			if err != nil {
				assert.EqualError(t, err, c.err, "case", c.str)
			} else {
				t.Errorf("Expected error but got %s:%d for %s", addr, port, c.str)
			}
		} else {
			assert.Equal(t, c.addr, addr, "case", c.str)
			assert.Equal(t, c.port, port, "case", c.str)
		}
	}
}
