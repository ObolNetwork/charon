// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package peerinfo_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/peerinfo"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestPeerInfo(t *testing.T) {
	now := time.Now()
	const gitCommit = "1234567"

	// when a major release happens, charon will only be compatible with a single version
	versions := version.Supported()
	if len(versions) < 2 {
		versions = append(versions, versions...)
	}

	nodes := []struct {
		Version  version.SemVer
		LockHash []byte
		Offset   time.Duration
		Ignore   bool
	}{
		{
			Version:  versions[0],
			LockHash: []byte("abcdef"),
		},
		{
			Version:  versions[0],
			LockHash: []byte("abcdef"),
		},
		{
			Version:  versions[1],
			LockHash: []byte("000000"),
			Offset:   time.Minute,
		},
		{
			Version: semver(t, "v0.0"),
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

	for i := range n {
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

	nowFunc := func(i int) func() time.Time {
		return func() time.Time { return now.Add(nodes[i].Offset) }
	}

	for i := range n {
		node := nodes[i]

		// Most nodes are passive
		tickProvider := func() (<-chan time.Time, func()) {
			return nil, func() {}
		}
		metricSubmitter := func(peer.ID, time.Duration, string, string, time.Time, bool) {
			panic("unexpected metric submitted")
		}

		// Except node 0, which does a single poll of all other peers.
		if i == 0 {
			tickProvider = func() (<-chan time.Time, func()) {
				ch := make(chan time.Time, 1)
				ch <- now

				return ch, func() {}
			}

			var submittedMutex sync.Mutex
			var submitted int
			metricSubmitter = func(peerID peer.ID, clockOffset time.Duration, version, gitHash string, startTime time.Time, builderEnabled bool) {
				for i, tcpNode := range tcpNodes {
					if tcpNode.ID() != peerID {
						continue
					}
					node := nodes[i]
					require.Equal(t, node.Version.String(), version)
					require.Equal(t, gitCommit, gitHash)
					require.Equal(t, nowFunc(i)().Unix(), startTime.Unix())
					require.True(t, builderEnabled)

					submittedMutex.Lock()
					submitted++
					if submitted == n-2 { // Expect metrics from everyone but ourselves or the ignored node.
						cancel()
					}
					submittedMutex.Unlock()

					return
				}
				panic("unknown peer")
			}
		}

		peerInfo := peerinfo.NewForT(t, tcpNodes[i], peers, node.Version, node.LockHash, gitCommit, p2p.SendReceive, p2p.RegisterHandler,
			tickProvider, nowFunc(i), metricSubmitter, true)

		peerInfos = append(peerInfos, peerInfo)
	}

	for i := range n {
		if nodes[i].Ignore {
			continue
		}
		go peerInfos[i].Run(ctx)
	}

	<-ctx.Done()
	cancel()
}

func semver(t *testing.T, v string) version.SemVer {
	t.Helper()

	sv, err := version.Parse(v)
	require.NoError(t, err)

	return sv
}
