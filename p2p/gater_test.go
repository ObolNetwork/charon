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

package p2p_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestInterceptSecured(t *testing.T) {
	tests := []struct {
		config peer.ID
		query  peer.ID
		allow  bool
	}{
		{"peer", "unknown", false},
		{"peer", "peer", true},
	}

	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			c, err := p2p.NewConnGater([]peer.ID{test.config}, nil)
			require.NoError(t, err)

			allow := c.InterceptSecured(0, test.query, nil)
			require.Equal(t, test.allow, allow)
		})
	}
}

func TestP2PConnGating(t *testing.T) {
	c, err := p2p.NewConnGater(nil, nil)
	require.NoError(t, err)

	keyA, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	require.NoError(t, err)
	nodeA, err := libp2p.New(
		libp2p.Identity(keyA),
		libp2p.ConnectionGater(c),
		libp2p.ListenAddrs(testutil.AvailableMultiAddr(t)))
	testutil.SkipIfBindErr(t, err)
	require.NoError(t, err)

	keyB, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	require.NoError(t, err)
	nodeB, err := libp2p.New(
		libp2p.Identity(keyB),
		libp2p.ListenAddrs(testutil.AvailableMultiAddr(t)),
	)
	testutil.SkipIfBindErr(t, err)
	require.NoError(t, err)

	addr := peer.AddrInfo{
		ID:    nodeB.ID(),
		Addrs: nodeB.Addrs(),
	}

	err = nodeA.Connect(context.Background(), addr)
	require.Error(t, err)
	require.Contains(t, err.Error(), fmt.Sprintf("gater rejected connection with peer %s", addr.ID))
}

func TestOpenGater(t *testing.T) {
	gater := p2p.NewOpenGater()
	require.True(t, gater.InterceptSecured(0, "", nil))
}
