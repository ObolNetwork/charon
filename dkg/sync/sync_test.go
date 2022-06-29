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

package sync_test

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/libp2p/go-libp2p"
	libp2pcrypto "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cmd"
	"github.com/obolnetwork/charon/dkg"
	"github.com/obolnetwork/charon/dkg/sync"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -run=TestAwaitAllConnected -race

func TestAwaitConnected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start Server
	serverHost, _ := newSyncHost(t, 0)

	// Start Client
	clientHost, key := newSyncHost(t, 1)
	require.NotEqual(t, clientHost.ID().String(), serverHost.ID().String())

	err := serverHost.Connect(ctx, peer.AddrInfo{
		ID:    clientHost.ID(),
		Addrs: clientHost.Addrs(),
	})
	require.NoError(t, err)

	hash := testutil.RandomBytes32()
	hashSig, err := key.Sign(hash)
	require.NoError(t, err)

	serverCtx := log.WithTopic(ctx, "server")
	_ = sync.NewServer(serverCtx, serverHost, []p2p.Peer{{ID: clientHost.ID()}}, hash, nil)

	clientCtx := log.WithTopic(context.Background(), "client")
	client := sync.NewClient(clientCtx, clientHost, p2p.Peer{ID: serverHost.ID()}, hashSig, nil)

	require.NoError(t, client.AwaitConnected())
}

func TestAwaitAllConnected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const numClients = 3
	server, clients := testGetServerAndClients(t, ctx, numClients)

	for i := 0; i < numClients; i++ {
		require.NoError(t, clients[i].AwaitConnected())
	}

	require.NoError(t, server.AwaitAllConnected())
}

func TestAwaitAllShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const numClients = 3
	server, clients := testGetServerAndClients(t, ctx, numClients)

	for i := 0; i < numClients; i++ {
		require.NoError(t, clients[i].Shutdown())
	}

	require.NoError(t, server.AwaitAllShutdown())
}

func TestSyncWithBootnode(t *testing.T) {
	const nodes = 4
	lock, keys, _ := cluster.NewForT(t, 1, nodes, nodes, 0)
	def := lock.Definition

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start bootnode
	bootnode, errChan := startBootnode(ctx, t)

	// Setup
	dir, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	conf := dkg.Config{
		DataDir: dir,
		P2P: p2p.Config{
			UDPBootnodes: []string{bootnode},
		},
		Log:     log.DefaultConfig(),
		TestDef: &def,
	}

	var eg errgroup.Group
	for i := 0; i < len(def.Operators); i++ {
		conf := conf
		conf.DataDir = path.Join(dir, fmt.Sprintf("node%d", i))
		conf.P2P.TCPAddrs = []string{testutil.AvailableAddr(t).String()}
		conf.P2P.UDPAddr = testutil.AvailableAddr(t).String()

		require.NoError(t, os.MkdirAll(conf.DataDir, 0o755))
		err := crypto.SaveECDSA(p2p.KeyPath(conf.DataDir), keys[i])
		require.NoError(t, err)

		eg.Go(func() error {
			return syncRun(ctx, conf)
		})
		if i == 0 {
			// Allow node0 some time to startup, this just mitigates startup races and backoffs but isn't required.
			time.Sleep(time.Millisecond * 100)
		}
	}

	// Wait until complete
	runChan := make(chan error, 1)
	go func() {
		runChan <- eg.Wait()
	}()

	select {
	case err := <-errChan:
		// If this returns first, something went wrong with the bootnode and the test will fail.
		cancel()
		testutil.SkipIfBindErr(t, err)
		require.Fail(t, "bootnode error: %v", err)
	case err := <-runChan:
		cancel()
		testutil.SkipIfBindErr(t, err)
		require.NoError(t, err)
	}
}

func syncRun(ctx context.Context, conf dkg.Config) error {
	conf.Log.Level = zapcore.InfoLevel.String()
	if err := log.InitLogger(conf.Log); err != nil {
		return err
	}

	def := *conf.TestDef
	peers, err := def.Peers()
	if err != nil {
		return err
	}

	key, err := p2p.LoadPrivKey(conf.DataDir)
	if err != nil {
		return err
	}

	priv, err := libp2pcrypto.UnmarshalSecp256k1PrivateKey(crypto.FromECDSA(key))
	if err != nil {
		return errors.Wrap(err, "libp2p k1 key")
	}

	tcpNode, shutdown, err := setupP2P(ctx, key, conf.P2P, peers)
	if err != nil {
		return err
	}
	defer shutdown()

	defHash, err := def.HashTreeRoot()
	if err != nil {
		return errors.Wrap(err, "hash definition")
	}

	// Sign definition hash with charon-enr-private-key
	hashSig, err := priv.Sign(defHash[:])
	if err != nil {
		return errors.Wrap(err, "sign definition hash")
	}

	server := sync.NewServer(ctx, tcpNode, peers, defHash[:], nil)
	var clients []*sync.Client
	for _, peer := range peers {
		if peer.ID == tcpNode.ID() {
			continue
		}
		c := sync.NewClient(ctx, tcpNode, peer, hashSig, nil)
		clients = append(clients, c)
	}

	for _, c := range clients {
		if err = c.AwaitConnected(); err != nil {
			return errors.Wrap(err, "client await connected")
		}
	}

	if err = server.AwaitAllConnected(); err != nil {
		return errors.Wrap(err, "server await all connected")
	}

	// Shutdown all clients and server
	for _, c := range clients {
		if err = c.Shutdown(); err != nil {
			return errors.Wrap(err, "client shutdown")
		}
	}

	if err = server.AwaitAllShutdown(); err != nil {
		return errors.Wrap(err, "await all shutdown")
	}

	return nil
}

func testGetServerAndClients(t *testing.T, ctx context.Context, num int) (*sync.Server, []*sync.Client) {
	t.Helper()

	seed := 0
	serverHost, _ := newSyncHost(t, int64(seed))
	var (
		peers       []p2p.Peer
		keys        []libp2pcrypto.PrivKey
		clientHosts []host.Host
	)
	for i := 0; i < num; i++ {
		seed++
		clientHost, key := newSyncHost(t, int64(seed))
		require.NotEqual(t, clientHost.ID().String(), serverHost.ID().String())

		err := serverHost.Connect(ctx, peer.AddrInfo{
			ID:    clientHost.ID(),
			Addrs: clientHost.Addrs(),
		})
		require.NoError(t, err)

		clientHosts = append(clientHosts, clientHost)
		keys = append(keys, key)
		peers = append(peers, p2p.Peer{ID: clientHost.ID()})
	}

	hash := testutil.RandomBytes32()
	server := sync.NewServer(log.WithTopic(ctx, "server"), serverHost, peers, hash, nil)

	var clients []*sync.Client
	for i := 0; i < num; i++ {
		hashSig, err := keys[i].Sign(hash)
		require.NoError(t, err)

		client := sync.NewClient(log.WithTopic(context.Background(), "client"), clientHosts[i], p2p.Peer{ID: serverHost.ID()}, hashSig, nil)
		clients = append(clients, client)
	}

	return server, clients
}

func newSyncHost(t *testing.T, seed int64) (host.Host, libp2pcrypto.PrivKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(crypto.S256(), rand.New(rand.NewSource(seed)))
	require.NoError(t, err)

	priv, err := libp2pcrypto.UnmarshalSecp256k1PrivateKey(crypto.FromECDSA(key))
	require.NoError(t, err)

	addr := testutil.AvailableAddr(t)
	multiAddr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d", addr.IP, addr.Port))
	require.NoError(t, err)

	host, err := libp2p.New(libp2p.ListenAddrs(multiAddr), libp2p.Identity(priv))
	require.NoError(t, err)

	return host, priv
}

// startBootnode starts a charon bootnode and returns its http ENR endpoint.
func startBootnode(ctx context.Context, t *testing.T) (string, <-chan error) {
	t.Helper()

	dir, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	addr := testutil.AvailableAddr(t).String()

	errChan := make(chan error, 1)
	go func() {
		errChan <- cmd.RunBootnode(ctx, cmd.BootnodeConfig{
			DataDir:  dir,
			HTTPAddr: addr,
			P2PConfig: p2p.Config{
				UDPAddr:  testutil.AvailableAddr(t).String(),
				TCPAddrs: []string{testutil.AvailableAddr(t).String()},
			},
			LogConfig: log.Config{
				Level:  "error",
				Format: "console",
			},
			AutoP2PKey: true,
			P2PRelay:   true,
		})
	}()

	endpoint := "http://" + addr + "/enr"

	// Wait for bootnode to become available.
	for ctx.Err() == nil {
		_, err := http.Get(endpoint)
		if err == nil {
			break
		}
		time.Sleep(time.Millisecond * 100)
	}

	return endpoint, errChan
}

// setupP2P returns a started libp2p tcp node and a shutdown function.
func setupP2P(ctx context.Context, key *ecdsa.PrivateKey, p2pConf p2p.Config, peers []p2p.Peer) (host.Host, func(), error) {
	localEnode, db, err := p2p.NewLocalEnode(p2pConf, key)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to open enode")
	}

	bootnodes, err := p2p.NewUDPBootnodes(ctx, p2pConf, peers, localEnode.ID())
	if err != nil {
		return nil, nil, errors.Wrap(err, "new bootnodes")
	}

	udpNode, err := p2p.NewUDPNode(p2pConf, localEnode, key, bootnodes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "")
	}

	relays, err := p2p.NewRelays(p2pConf, bootnodes)
	if err != nil {
		return nil, nil, err
	}

	tcpNode, err := p2p.NewTCPNode(p2pConf, key, p2p.NewOpenGater(), udpNode, peers, relays)
	if err != nil {
		return nil, nil, errors.Wrap(err, "")
	}

	for _, relay := range relays {
		go func(relay p2p.Peer) {
			err := p2p.NewRelayReserver(tcpNode, relay)(ctx)
			if err != nil {
				log.Error(ctx, "Reserve relay error", err)
			}
		}(relay)
	}

	return tcpNode, func() {
		db.Close()
		udpNode.Close()
		_ = tcpNode.Close()
	}, nil
}
