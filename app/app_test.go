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

package app_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/p2p"
)

func TestPingCluster(t *testing.T) {
	const n = 3
	ctx, cancel := context.WithCancel(context.Background())

	manifest, p2pKeys, _ := cluster.NewForT(t, n, n)

	records, err := manifest.ParsedENRs()
	require.NoError(t, err)

	pingCh := make(chan peer.ID, 1)

	var eg errgroup.Group

	for i := 0; i < n; i++ {

		conf := app.Config{
			P2P: p2p.Config{
				TCPAddrs: []string{addrFromENR(t, records[i])}, // Use p2p address defined in each ENR
				UDPAddr:  availableAddr(t).String(),            // Random discv5 address
			},
			MonitoringAddr:   availableAddr(t).String(), // Random monitoring address
			ValidatorAPIAddr: availableAddr(t).String(), // Random validatorapi address
			TestConfig: app.TestConfig{
				Manifest:        manifest,
				P2PKey:          p2pKeys[i],
				ConnectAttempts: 2,
				PingCallback: func(p peer.ID) {
					select {
					case pingCh <- p:
					default:
					}
				},
			},
		}

		eg.Go(func() error {
			return app.Run(ctx, conf)
		})
	}

	// Wait until we detect n*2 pings.
	// TODO(corver): Make re-connects more robust.
	go func() {
		for i := 0; i < n*2; i++ {
			select {
			case p := <-pingCh:
				t.Logf("Received ping from: %v", p2p.ShortID(p))
			case <-time.After(time.Second * 5):
				require.Fail(t, "ping timeout")
				break
			}
		}
		cancel()
	}()

	require.NoError(t, eg.Wait())
}

// availableAddr returns an available local tcp address.
func availableAddr(t *testing.T) *net.TCPAddr {
	t.Helper()

	l, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	addr, err := net.ResolveTCPAddr(l.Addr().Network(), l.Addr().String())
	require.NoError(t, err)

	return addr
}

// addrFromENR returns the "<ip4>:<port>" address stored in the ENR.
func addrFromENR(t *testing.T, record enr.Record) string {
	t.Helper()

	info, err := cluster.PeerInfoFromENR(record)
	require.NoError(t, err)
	port, err := info.Addrs[0].ValueForProtocol(multiaddr.P_TCP)
	require.NoError(t, err)
	ip, err := info.Addrs[0].ValueForProtocol(multiaddr.P_IP4)
	require.NoError(t, err)

	return ip + ":" + port
}
