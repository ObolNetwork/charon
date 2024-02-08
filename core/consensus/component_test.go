// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus_test

import (
	"context"
	"fmt"
	"math/rand"
	"testing"

	"github.com/libp2p/go-libp2p"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/consensus"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestComponent(t *testing.T) {
	tests := []struct {
		name      string
		threshold int
		nodes     int
	}{
		{
			name:      "2-of-3",
			threshold: 2,
			nodes:     3,
		},
		{
			name:      "3-of-4",
			threshold: 3,
			nodes:     4,
		},
		{
			name:      "4-of-4",
			threshold: 4,
			nodes:     4,
		},
		{
			name:      "4-of-6",
			threshold: 4,
			nodes:     6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testComponent(t, tt.threshold, tt.nodes)
		})
	}
}

// testComponent tests a consensus instance with size of threshold-of-nodes.
// Note it only instantiates the minimum amount of peers, ie threshold.
func testComponent(t *testing.T, threshold, nodes int) {
	t.Helper()
	seed := 0
	random := rand.New(rand.NewSource(int64(seed)))
	lock, p2pkeys, _ := cluster.NewForT(t, 1, threshold, nodes, seed, random)

	var (
		peers       []p2p.Peer
		hosts       []host.Host
		hostsInfo   []peer.AddrInfo
		components  []*consensus.Component
		results     = make(chan core.UnsignedDataSet, threshold)
		runErrs     = make(chan error, threshold)
		sniffed     = make(chan int, threshold)
		ctx, cancel = context.WithCancel(context.Background())
	)
	defer cancel()

	// Create hosts and enrs (ony for threshold).
	for i := 0; i < threshold; i++ {
		addr := testutil.AvailableAddr(t)
		mAddr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d", addr.IP, addr.Port))
		require.NoError(t, err)

		priv := (*libp2pcrypto.Secp256k1PrivateKey)(p2pkeys[i])
		h, err := libp2p.New(libp2p.Identity(priv), libp2p.ListenAddrs(mAddr))
		testutil.SkipIfBindErr(t, err)
		require.NoError(t, err)

		record, err := enr.Parse(lock.Operators[i].ENR)
		require.NoError(t, err)

		p, err := p2p.NewPeerFromENR(record, i)
		require.NoError(t, err)

		hostsInfo = append(hostsInfo, peer.AddrInfo{ID: h.ID(), Addrs: h.Addrs()})
		peers = append(peers, p)
		hosts = append(hosts, h)
	}

	// Connect each host with its peers
	for i := 0; i < threshold; i++ {
		for j := 0; j < threshold; j++ {
			if i == j {
				continue
			}
			hosts[i].Peerstore().AddAddrs(hostsInfo[j].ID, hostsInfo[j].Addrs, peerstore.PermanentAddrTTL)
		}

		sniffer := func(msgs *pbv1.SniffedConsensusInstance) {
			sniffed <- len(msgs.Msgs)
		}

		gaterFunc := func(core.Duty) bool { return true }

		c, err := consensus.New(hosts[i], new(p2p.Sender), peers, p2pkeys[i], testDeadliner{}, gaterFunc, sniffer)
		require.NoError(t, err)
		c.Subscribe(func(_ context.Context, _ core.Duty, set core.UnsignedDataSet) error {
			results <- set
			return nil
		})
		c.Start(log.WithCtx(ctx, z.Int("node", i)))

		components = append(components, c)
	}

	pubkey := testutil.RandomCorePubKey(t)

	// Start all components.
	for i, c := range components {
		go func(ctx context.Context, i int, c *consensus.Component) {
			runErrs <- c.Propose(
				log.WithCtx(ctx, z.Int("node", i), z.Str("peer", p2p.PeerName(hosts[i].ID()))),
				core.Duty{Type: core.DutyAttester, Slot: 1},
				core.UnsignedDataSet{pubkey: testutil.RandomCoreAttestationData(t)},
			)
		}(ctx, i, c)
	}

	var (
		count  int
		result core.UnsignedDataSet
	)
	for {
		select {
		case err := <-runErrs:
			testutil.RequireNoError(t, err)
		case res := <-results:
			t.Logf("Got result: %#v", res)
			if count == 0 {
				result = res
			} else {
				require.EqualValues(t, result, res)
			}
			count++
		}

		if count == threshold {
			break
		}
	}

	cancel()

	for i := 0; i < threshold; i++ {
		require.NotZero(t, <-sniffed)
	}
}

// testDeadliner is a mock deadliner implementation.
type testDeadliner struct {
	deadlineChan chan core.Duty
}

func (testDeadliner) Add(core.Duty) bool {
	return true
}

func (t testDeadliner) C() <-chan core.Duty {
	return t.deadlineChan
}
