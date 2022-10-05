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

package peerinfo_test

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/peerinfo"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestPeerInfo(t *testing.T) {
	now := time.Now()

	nodes := []struct {
		Version  string
		LockHash []byte
		Offset   time.Duration
		Ignore   bool
	}{
		{
			Version:  "local",
			LockHash: []byte("abcdef"),
		},
		{
			Version:  "ok",
			LockHash: []byte("abcdef"),
		},
		{
			Version:  "nok",
			LockHash: []byte("000000"),
			Offset:   time.Minute,
		},
		{
			Version: "ignored",
			Ignore:  true,
		},
	}

	var (
		ctx, cancel = context.WithCancel(context.Background())
		n           = len(nodes)
		tcpNodes    []host.Host
		peers       []peer.ID
		peerInfos   []*peerinfo.PeerInfo
	)

	for i := 0; i < n; i++ {
		tcpNode := testutil.CreateHost(t, testutil.AvailableAddr(t))
		for j, other := range tcpNodes {
			tcpNode.Peerstore().AddAddrs(other.ID(), other.Addrs(), peerstore.PermanentAddrTTL)
			other.Peerstore().AddAddrs(tcpNode.ID(), tcpNode.Addrs(), peerstore.PermanentAddrTTL)
			if !nodes[i].Ignore {
				err := tcpNode.Peerstore().SetProtocols(other.ID(), "/charon/peerinfo/1.0.0")
				require.NoError(t, err)
			}
			if !nodes[j].Ignore {
				err := other.Peerstore().SetProtocols(tcpNode.ID(), "/charon/peerinfo/1.0.0")
				require.NoError(t, err)
			}
		}

		tcpNodes = append(tcpNodes, tcpNode)
		peers = append(peers, tcpNode.ID())
	}

	for i := 0; i < n; i++ {
		node := nodes[i]

		// Most nodes are passive
		tickProvider := func() (<-chan time.Time, func()) {
			return nil, func() {}
		}
		metricSubmitter := func(peer.ID, time.Duration, string) {
			panic("unexpected metric submitted")
		}

		// Except node 0, which does a single poll of all other peers.
		if i == 0 {
			tickProvider = func() (<-chan time.Time, func()) {
				ch := make(chan time.Time, 1)
				ch <- now
				return ch, func() {}
			}

			var submitted int
			metricSubmitter = func(peerID peer.ID, clockOffset time.Duration, version string) {
				for i, tcpNode := range tcpNodes {
					if tcpNode.ID() != peerID {
						continue
					}
					node := nodes[i]
					require.Equal(t, node.Version, version)
					require.Equal(t, node.Offset, clockOffset)

					submitted++
					if submitted == n-2 { // Expect metrics from everyone but ourselves or the ignored node.
						cancel()
					}

					return
				}
				panic("unknown peer")
			}
		}

		peerInfo := peerinfo.NewForT(t, tcpNodes[i], peers, node.Version, node.LockHash, p2p.SendReceive, p2p.RegisterHandler,
			tickProvider, func() time.Time { return now.Add(node.Offset) }, metricSubmitter)

		peerInfos = append(peerInfos, peerInfo)
	}

	for i := 0; i < n; i++ {
		if nodes[i].Ignore {
			continue
		}
		go peerInfos[i].Run(ctx)
	}

	<-ctx.Done()
	cancel()
}
