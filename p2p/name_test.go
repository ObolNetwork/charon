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
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/p2p"
)

func TestPeerName(t *testing.T) {
	enr := "enr:-JG4QBqxg9KCQ1vnvVagJsg08-qbtOjJ9Mkcm3d-FOX1Z2dqdw6Rp0S5lBRC2Uh4_Hk6KvyZoRJY5VGlkVb8scEWXaeGAYDhsvrogmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQMsMU_1-8n0xkoOJD9v-DOSjmc8FFTXv9xWW8gqbZxlcIN0Y3CCPoODdWRwgj6E"
	record, err := p2p.DecodeENR(enr)
	require.NoError(t, err)

	peer, err := p2p.NewPeer(record, 0)
	require.NoError(t, err)

	require.Equal(t, peer.Name, "happy-floor")
}

func Test(t *testing.T) {
	tests := []struct {
		peerID string
		name   string
	}{
		{
			peerID: "16Uiu2HAmDTemdrDfAgG1DX5q3NmfART3PcTFZe69yrNHdde3Qq3v",
			name:   "different-course",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p, err := peer.Decode(test.peerID)
			require.NoError(t, err)
			require.Equal(t, test.name, p2p.PeerName(p))
		})
	}
}
