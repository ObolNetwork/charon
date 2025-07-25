// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p

import (
	"context"
	"testing"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -clean -update

func TestNamedAddr(t *testing.T) {
	// Copied from github.com/multiformats/go-multiaddr/multiaddr_test.go
	addrs := []string{
		"/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234",
		"/p2p/k2k4r8oqamigqdo6o7hsbfwd45y70oyynp98usk7zmyfrzpqxh1pohl7/tcp/1234",
		"/ip4/127.0.0.1/udp/1234",
		"/ip4/127.0.0.1/udp/0",
		"/ip4/127.0.0.1/tcp/1234",
		"/ip4/127.0.0.1/tcp/1234/",
		"/ip4/127.0.0.1/udp/1234/quic",
		"/ip4/127.0.0.1/udp/1234/quic-v1", // Manually added
		"/ip4/127.0.0.1/udp/1234/quic/webtransport",
		"/ip4/127.0.0.1/udp/1234/quic/webtransport/certhash/b2uaraocy6yrdblb4sfptaddgimjmmpy",
		"/ip4/127.0.0.1/udp/1234/quic/webtransport/certhash/b2uaraocy6yrdblb4sfptaddgimjmmpy/certhash/zQmbWTwYGcmdyK9CYfNBcfs9nhZs17a6FQ4Y8oea278xx41",
		"/ip4/127.0.0.1/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC",
		"/ip4/127.0.0.1/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234",
		"/ip4/127.0.0.1/ipfs/k2k4r8oqamigqdo6o7hsbfwd45y70oyynp98usk7zmyfrzpqxh1pohl7",
		"/ip4/127.0.0.1/ipfs/k2k4r8oqamigqdo6o7hsbfwd45y70oyynp98usk7zmyfrzpqxh1pohl7/tcp/1234",
		"/ip4/127.0.0.1/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC",
		"/ip4/127.0.0.1/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234",
		"/ip4/127.0.0.1/p2p/k2k4r8oqamigqdo6o7hsbfwd45y70oyynp98usk7zmyfrzpqxh1pohl7",
		"/ip4/127.0.0.1/p2p/k2k4r8oqamigqdo6o7hsbfwd45y70oyynp98usk7zmyfrzpqxh1pohl7/tcp/1234",
		"/unix/a/b/c/d/e",
		"/unix/stdio",
		"/ip4/1.2.3.4/tcp/80/unix/a/b/c/d/e/f",
		"/ip4/127.0.0.1/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234/unix/stdio",
	}

	var resp []string

	for _, addr := range addrs {
		a, err := ma.NewMultiaddr(addr)
		require.NoError(t, err)

		resp = append(resp, NamedAddr(a))
	}

	testutil.RequireGoldenJSON(t, resp)
}

func TestDialErrMsgs(t *testing.T) {
	ctx := context.Background()

	badAddr, err := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/1234/")
	require.NoError(t, err)

	hostA := testutil.CreateHost(t, testutil.AvailableAddr(t))
	hostB := testutil.CreateHost(t, testutil.AvailableAddr(t), libp2p.ConnectionGater(closedGater{}))
	hostBAddr := hostB.Addrs()[0]

	hostA.Peerstore().AddAddr(hostB.ID(), hostBAddr, peerstore.TempAddrTTL) // Gater will block these
	hostA.Peerstore().AddAddr(hostB.ID(), badAddr, peerstore.TempAddrTTL)   // Connection refused

	_, err = hostA.Network().DialPeer(ctx, hostB.ID()) // Try dial
	require.Error(t, err)

	msgs, ok := dialErrMsgs(err)
	require.True(t, ok)
	require.False(t, hasErrDialBackoff(err))
	require.Len(t, msgs, 2)
	require.Contains(t, msgs[badAddr.String()], "connection refused")
	require.Contains(t, msgs[hostBAddr.String()], "failed to negotiate security protocol")

	_, err = hostA.Network().DialPeer(ctx, hostB.ID()) // Try dial again
	require.Error(t, err)

	msgs, ok = dialErrMsgs(err)
	require.True(t, ok)
	require.True(t, hasErrDialBackoff(err))
	require.Len(t, msgs, 2)
	require.Contains(t, msgs[badAddr.String()], "dial backoff")
	require.Contains(t, msgs[hostBAddr.String()], "dial backoff")
}

// closedGater is a connection gater that blocks all connections.
type closedGater struct{}

func (closedGater) InterceptPeerDial(peer.ID) bool {
	return false
}

func (closedGater) InterceptAddrDial(peer.ID, ma.Multiaddr) bool {
	return false
}

func (closedGater) InterceptAccept(network.ConnMultiaddrs) bool {
	return false
}

func (closedGater) InterceptSecured(network.Direction, peer.ID, network.ConnMultiaddrs) bool {
	return false
}

func (closedGater) InterceptUpgraded(network.Conn) (bool, control.DisconnectReason) {
	return false, 0
}
