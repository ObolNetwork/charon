// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p_test

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/p2p"
)

func TestPeerName(t *testing.T) {
	enrStr := "enr:-JG4QBqxg9KCQ1vnvVagJsg08-qbtOjJ9Mkcm3d-FOX1Z2dqdw6Rp0S5lBRC2Uh4_Hk6KvyZoRJY5VGlkVb8scEWXaeGAYDhsvrogmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQMsMU_1-8n0xkoOJD9v-DOSjmc8FFTXv9xWW8gqbZxlcIN0Y3CCPoODdWRwgj6E"
	record, err := enr.Parse(enrStr)
	require.NoError(t, err)

	p, err := p2p.NewPeerFromENR(record, 0)
	require.NoError(t, err)

	require.Equal(t, p.Name, "happy-floor")
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
