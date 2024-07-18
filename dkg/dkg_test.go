// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cmd/relay"
	"github.com/obolnetwork/charon/dkg"
	dkgsync "github.com/obolnetwork/charon/dkg/sync"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/deposit"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/eth2util/registration"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil"
)

func TestDKG(t *testing.T) {
	const (
		nodes = 3
		vals  = 2
	)

	withAlgo := func(algo string) func(*cluster.Definition) {
		return func(d *cluster.Definition) {
			d.DKGAlgorithm = algo
		}
	}

	withDepositAmounts := func(amounts []eth2p0.Gwei) func(*cluster.Definition) {
		return func(d *cluster.Definition) {
			d.DepositAmounts = amounts
		}
	}

	tests := []struct {
		name           string
		dkgAlgo        string
		version        string // Defaults to latest if empty
		depositAmounts []eth2p0.Gwei
		keymanager     bool
		publish        bool
	}{
		{
			name:    "frost_v16",
			version: "v1.6.0",
			dkgAlgo: "frost",
		},
		{
			name:    "frost_latest",
			dkgAlgo: "frost",
		},
		{
			name:    "with_partial_deposits",
			version: "v1.8.0",
			dkgAlgo: "frost",
			depositAmounts: []eth2p0.Gwei{
				8 * deposit.OneEthInGwei,
				16 * deposit.OneEthInGwei,
				8 * deposit.OneEthInGwei,
			},
		},
		{
			name:       "dkg with keymanager",
			dkgAlgo:    "frost",
			keymanager: true,
		},
		{
			name:    "dkg with lockfile publish",
			dkgAlgo: "frost",
			publish: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := []func(*cluster.Definition){
				withAlgo(test.dkgAlgo),
				withDepositAmounts(test.depositAmounts),
			}
			if test.version != "" {
				opts = append(opts, cluster.WithVersion(test.version))
			}

			seed := 1
			random := rand.New(rand.NewSource(int64(seed)))
			lock, keys, _ := cluster.NewForT(t, vals, nodes, nodes, seed, random, opts...)
			dir := t.TempDir()

			testDKG(t, lock.Definition, dir, keys, test.keymanager, test.publish)
			if !test.keymanager {
				verifyDKGResults(t, lock.Definition, dir)
			}
		})
	}
}

func testDKG(t *testing.T, def cluster.Definition, dir string, p2pKeys []*k1.PrivateKey, keymanager bool, publish bool) {
	t.Helper()

	require.NoError(t, def.VerifySignatures())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start relay.
	relayAddr := startRelay(ctx, t)

	// Setup config
	conf := dkg.Config{
		DataDir: dir,
		P2P: p2p.Config{
			Relays: []string{relayAddr},
		},
		Log: log.DefaultConfig(),
		TestConfig: dkg.TestConfig{
			Def: &def,
			StoreKeysFunc: func(secrets []tbls.PrivateKey, dir string) error {
				return keystore.StoreKeysInsecure(secrets, dir, keystore.ConfirmInsecureKeys)
			},
			SyncOpts: []func(*dkgsync.Client){dkgsync.WithPeriod(time.Millisecond * 50)},
		},
		ShutdownDelay:  1 * time.Second,
		PublishTimeout: 30 * time.Second,
		Timeout:        8 * time.Second,
	}

	allReceivedKeystores := make(chan struct{}) // Receives struct{} for each `numNodes` keystore intercepted by the keymanager server
	if keymanager {
		const testAuthToken = "test-auth-token"
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bearerAuthToken := strings.Split(r.Header.Get("Authorization"), " ")
			require.Equal(t, bearerAuthToken[0], "Bearer")
			require.Equal(t, bearerAuthToken[1], testAuthToken)

			go func() {
				allReceivedKeystores <- struct{}{}
			}()
		}))
		defer srv.Close()

		conf.KeymanagerAddr = srv.URL
		conf.KeymanagerAuthToken = testAuthToken
	}

	receivedLockfile := make(chan struct{}) // Receives string for lockfile intercepted by the obol-api server
	if publish {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			go func() {
				receivedLockfile <- struct{}{}
			}()
		}))
		defer srv.Close()

		conf.Publish = true
		conf.PublishAddr = srv.URL
	}

	// Run dkg for each node
	var eg errgroup.Group
	for i := 0; i < len(def.Operators); i++ {
		conf := conf
		conf.DataDir = path.Join(dir, fmt.Sprintf("node%d", i))
		conf.P2P.TCPAddrs = []string{testutil.AvailableAddr(t).String()}

		require.NoError(t, os.MkdirAll(conf.DataDir, 0o755))
		err := k1util.Save(p2pKeys[i], p2p.KeyPath(conf.DataDir))
		require.NoError(t, err)

		eg.Go(func() error {
			err := dkg.Run(peerCtx(ctx, i), conf)
			if err != nil {
				cancel()
			}

			return err
		})
		if i == 0 {
			// Allow node0 some time to startup, this just mitigates startup races and backoffs but isn't required.
			time.Sleep(time.Millisecond * 100)
		}
	}

	// Wait until complete
	err := eg.Wait()
	testutil.SkipIfBindErr(t, err)
	testutil.RequireNoError(t, err)

	// check that the privkey lock file has been deleted in all nodes at the end of dkg
	for i := 0; i < len(def.Operators); i++ {
		lockPath := path.Join(dir, fmt.Sprintf("node%d", i), "charon-enr-private-key.lock")

		_, openErr := os.Open(lockPath)
		require.ErrorIs(t, openErr, os.ErrNotExist)
	}

	if keymanager {
		// Wait until all keystores are received by the keymanager server
		expectedReceives := len(def.Operators)
		for expectedReceives > 0 {
			<-allReceivedKeystores
			expectedReceives--
		}

		t.Log("All keystores received 🎉")
	}

	if publish {
		expectedReceives := 1
		for expectedReceives > 0 {
			<-receivedLockfile
			expectedReceives--
		}

		t.Log("Lockfile published to obol-api 🎉")
	}
}

// startRelay starts a charon relay and returns its http multiaddr endpoint.
func startRelay(parentCtx context.Context, t *testing.T) string {
	t.Helper()

	dir := t.TempDir()

	addr := testutil.AvailableAddr(t).String()

	errChan := make(chan error, 1)
	go func() {
		err := relay.Run(parentCtx, relay.Config{
			DataDir:  dir,
			HTTPAddr: addr,
			P2PConfig: p2p.Config{
				TCPAddrs: []string{testutil.AvailableAddr(t).String()},
			},
			LogConfig: log.Config{
				Level:  "error",
				Format: "console",
			},
			AutoP2PKey:    true,
			MaxResPerPeer: 8,
			MaxConns:      1024,
		})
		if err != nil {
			log.Warn(parentCtx, "Relay stopped with error", err)
		} else {
			log.Info(parentCtx, "Relay stopped without error")
		}

		errChan <- err
	}()

	endpoint := "http://" + addr

	// Wait up to 5s for bootnode to become available.
	ctx, cancel := context.WithTimeout(parentCtx, 10*time.Second)
	defer cancel()

	isUp := make(chan struct{})
	go func() {
		for ctx.Err() == nil {
			_, err := http.Get(endpoint)
			if err != nil {
				time.Sleep(time.Millisecond * 100)
				continue
			}
			close(isUp)

			return
		}
	}()

	for {
		select {
		case <-ctx.Done():
			require.Fail(t, "Relay context canceled before startup")
			return ""
		case err := <-errChan:
			testutil.SkipIfBindErr(t, err)
			require.Fail(t, "Relay exitted before startup", "err=%v", err)

			return ""
		case <-isUp:
			return endpoint
		}
	}
}

func verifyDKGResults(t *testing.T, def cluster.Definition, dir string) {
	t.Helper()

	// Read generated lock and keystores from disk
	var (
		secretShares = make([][]tbls.PrivateKey, def.NumValidators)
		locks        []cluster.Lock
	)
	for i := 0; i < len(def.Operators); i++ {
		dataDir := path.Join(dir, fmt.Sprintf("node%d", i))
		keyFiles, err := keystore.LoadFilesUnordered(path.Join(dataDir, "/validator_keys"))
		require.NoError(t, err)
		require.Len(t, keyFiles, def.NumValidators)

		secrets, err := keyFiles.SequencedKeys()
		require.NoError(t, err)

		for j, secret := range secrets {
			secretShares[j] = append(secretShares[j], secret)
		}

		lockFile, err := os.ReadFile(path.Join(dataDir, "cluster-lock.json"))
		require.NoError(t, err)

		var lock cluster.Lock
		require.NoError(t, json.Unmarshal(lockFile, &lock))
		require.NoError(t, lock.VerifySignatures())
		locks = append(locks, lock)

		verifyDistValidators(t, lock, def)
	}

	// Ensure locks hashes are identical.
	var hash []byte
	for i, lock := range locks {
		if i == 0 {
			hash = lock.LockHash
		} else {
			require.Equal(t, hash, lock.LockHash)
		}
	}

	// 	Ensure keystores can generate valid tbls aggregate signature.
	for i := 0; i < def.NumValidators; i++ {
		var sigs []tbls.Signature
		for j := 0; j < len(def.Operators); j++ {
			msg := []byte("data")
			sig, err := tbls.Sign(secretShares[i][j], msg)
			require.NoError(t, err)
			sigs = append(sigs, sig)

			// Ensure all public shares can verify the partial signature
			for _, lock := range locks {
				if len(lock.Validators[i].PubShares) == 0 {
					continue
				}
				pk, err := tblsconv.PubkeyFromBytes(lock.Validators[i].PubShares[j])
				require.NoError(t, err)
				err = tbls.Verify(pk, msg, sig)
				require.NoError(t, err)
			}
		}
		_, err := tbls.Aggregate(sigs)
		require.NoError(t, err)
	}
}

func verifyDistValidators(t *testing.T, lock cluster.Lock, def cluster.Definition) {
	t.Helper()

	for j, val := range lock.Validators {
		// Assert Deposit Data
		depositAmounts := deposit.DedupAmounts(def.DepositAmounts)
		if len(depositAmounts) == 0 {
			depositAmounts = []eth2p0.Gwei{deposit.MaxDepositAmount}
		}
		require.Len(t, val.PartialDepositData, len(depositAmounts))

		// Assert Partial Deposit Data
		uniqueSigs := make(map[string]struct{})
		for i, amount := range depositAmounts {
			pdd := val.PartialDepositData[i]
			require.EqualValues(t, val.PubKey, pdd.PubKey)
			require.EqualValues(t, amount, pdd.Amount)
			uniqueSigs[hex.EncodeToString(pdd.Signature)] = struct{}{}
		}
		// Signatures must be unique for each deposit
		require.Len(t, uniqueSigs, len(depositAmounts))

		if !cluster.SupportPregenRegistrations(lock.Version) {
			require.Empty(t, val.BuilderRegistration.Signature)
			continue
		}

		// Assert Builder Registration
		require.EqualValues(t, val.PubKey, val.BuilderRegistration.Message.PubKey)
		require.EqualValues(t, registration.DefaultGasLimit, val.BuilderRegistration.Message.GasLimit)
		timestamp, err := eth2util.ForkVersionToGenesisTime(lock.ForkVersion)
		require.NoError(t, err)
		require.EqualValues(t, timestamp, val.BuilderRegistration.Message.Timestamp)

		// Verify registration signatures
		eth2Reg, err := registration.NewMessage(eth2p0.BLSPubKey(val.BuilderRegistration.Message.PubKey),
			fmt.Sprintf("%#x", val.BuilderRegistration.Message.FeeRecipient),
			uint64(val.BuilderRegistration.Message.GasLimit), val.BuilderRegistration.Message.Timestamp)
		require.NoError(t, err)

		sigRoot, err := registration.GetMessageSigningRoot(eth2Reg, eth2p0.Version(lock.ForkVersion))
		require.NoError(t, err)

		sig, err := tblsconv.SignatureFromBytes(val.BuilderRegistration.Signature)
		require.NoError(t, err)

		pubkey, err := tblsconv.PubkeyFromBytes(val.PubKey)
		require.NoError(t, err)

		err = tbls.Verify(pubkey, sigRoot[:], sig)
		require.NoError(t, err)

		require.EqualValues(t,
			lock.ValidatorAddresses[j].FeeRecipientAddress,
			fmt.Sprintf("%#x", val.BuilderRegistration.Message.FeeRecipient),
		)
	}
}

func TestSyncFlow(t *testing.T) {
	tests := []struct {
		name       string
		connect    []int // Initial connections
		disconnect []int // Drop some peers
		reconnect  []int // Connect remaining peers
		nodes      int
		vals       int
	}{
		{
			name:       "three_connect_one_disconnect",
			connect:    []int{0, 1, 3},
			disconnect: []int{3},
			reconnect:  []int{2, 3},
			vals:       2,
			nodes:      4,
		},
		{
			name:       "four_connect_two_disconnect",
			connect:    []int{0, 1, 2, 3},
			disconnect: []int{0, 1},
			reconnect:  []int{0, 1, 4},
			vals:       4,
			nodes:      5,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := 0
			random := rand.New(rand.NewSource(int64(seed)))
			lock, keys, _ := cluster.NewForT(t, test.vals, test.nodes, test.nodes, seed, random)

			pIDs, err := lock.PeerIDs()
			require.NoError(t, err)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			ctx = log.WithTopic(ctx, "test")
			relayAddr := startRelay(ctx, t)
			dir := t.TempDir()
			configs := getConfigs(t, lock.Definition, keys, dir, relayAddr)

			var (
				// Initialise slice with the given number of nodes since this table tests input node indices as testcases.
				stopDkgs   = make([]context.CancelFunc, test.nodes)
				cTracker   = newConnTracker(pIDs)
				dkgErrChan = make(chan error)
			)

			// Start DKG for initial peers.
			for _, idx := range test.connect {
				log.Info(ctx, "Starting initial peer", z.Int("peer_index", idx))
				configs[idx].TestConfig.SyncCallback = cTracker.Set
				stopDkgs[idx] = startNewDKG(t, peerCtx(ctx, idx), configs[idx], dkgErrChan)
			}

			// Wait for initial peers to connect with each other.
			expect := len(test.connect) - 1
			for _, idx := range test.connect {
				log.Info(ctx, "Waiting for initial peer count",
					z.Int("peer_index", idx), z.Int("expect", expect))
				cTracker.AwaitN(t, dkgErrChan, expect, idx)
			}

			// Stop some peers.
			for _, idx := range test.disconnect {
				log.Info(ctx, "Stopping peer", z.Int("peer_index", idx))
				stopDkgs[idx]()

				// Wait for this dkg process to return.
				err := <-dkgErrChan
				require.ErrorIs(t, err, context.Canceled)
			}

			// Wait for remaining-initial peers to update connection counts.
			expect = len(test.connect) - len(test.disconnect) - 1
			for _, idx := range test.connect {
				if slices.Contains(test.disconnect, idx) {
					continue
				}

				configs[idx].TestConfig.SyncCallback = cTracker.Set

				log.Info(ctx, "Waiting for remaining-initial peer count",
					z.Int("peer_index", idx), z.Int("expect", expect))
				cTracker.AwaitN(t, dkgErrChan, expect, idx)
			}

			// Start other peers.
			for _, idx := range test.reconnect {
				log.Info(ctx, "Starting remaining peer", z.Int("peer_index", idx))
				stopDkgs[idx] = startNewDKG(t, peerCtx(ctx, idx), configs[idx], dkgErrChan)
			}

			// Wait for all peer DKG processes to complete.
			var disconnectedCount int
			for err := range dkgErrChan {
				testutil.SkipIfBindErr(t, err)
				require.NoError(t, err)
				disconnectedCount++
				if disconnectedCount == test.nodes {
					break
				}
			}

			// Assert DKG results for all DKG processes.
			verifyDKGResults(t, lock.Definition, dir)
		})
	}
}

func newConnTracker(peerIDs []peer.ID) *connTracker {
	return &connTracker{
		counts:  make(map[int]int),
		peerIDs: peerIDs,
	}
}

// connTracker tracks the number of connections for each peer.
type connTracker struct {
	mu      sync.Mutex
	counts  map[int]int
	peerIDs []peer.ID
}

func (c *connTracker) count(idx int) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.counts[idx]
}

func (c *connTracker) AwaitN(t *testing.T, dkgErrChan chan error, n int, peerIdx int) {
	t.Helper()

	ticker := time.NewTicker(time.Millisecond * 100)
	defer ticker.Stop()

	timeout := time.NewTimer(time.Second * 5)
	defer timeout.Stop()

	for {
		select {
		case <-timeout.C:
			require.Fail(t, "timeout", "expected %d connections for peer %d, got %d", n, peerIdx, c.count(peerIdx))
		case err := <-dkgErrChan:
			testutil.SkipIfBindErr(t, err)
			require.Failf(t, "DKG exited", "err=%v", err)
		case <-ticker.C:
			if c.count(peerIdx) == n {
				return
			}
		}
	}
}

func (c *connTracker) Set(n int, pID peer.ID) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i, p := range c.peerIDs {
		if p == pID {
			c.counts[i] = n
			return
		}
	}

	panic("peer not found")
}

func peerCtx(ctx context.Context, idx int) context.Context {
	return log.WithCtx(ctx, z.Int("peer_index", idx))
}

func getConfigs(t *testing.T, def cluster.Definition, keys []*k1.PrivateKey, dir, bootnode string) []dkg.Config {
	t.Helper()
	tcpNodeCallback := testutil.NewTCPNodeCallback(t, dkgsync.Protocols()...)

	var configs []dkg.Config
	for i := 0; i < len(def.Operators); i++ {
		conf := dkg.Config{
			DataDir: path.Join(dir, fmt.Sprintf("node%d", i)),
			P2P: p2p.Config{
				Relays:   []string{bootnode},
				TCPAddrs: []string{testutil.AvailableAddr(t).String()},
			},
			Log: log.DefaultConfig(),
			TestConfig: dkg.TestConfig{
				Def: &def,
				StoreKeysFunc: func(secrets []tbls.PrivateKey, dir string) error {
					return keystore.StoreKeysInsecure(secrets, dir, keystore.ConfirmInsecureKeys)
				},
				TCPNodeCallback: tcpNodeCallback,
			},
			Timeout: 8 * time.Second,
		}
		require.NoError(t, os.MkdirAll(conf.DataDir, 0o755))

		err := k1util.Save(keys[i], p2p.KeyPath(conf.DataDir))
		require.NoError(t, err)

		configs = append(configs, conf)
	}

	return configs
}

func startNewDKG(t *testing.T, parentCtx context.Context, config dkg.Config, dkgErrChan chan error) context.CancelFunc {
	t.Helper()

	ctx, cancel := context.WithCancel(parentCtx)

	go func() {
		err := dkg.Run(ctx, config)
		log.Info(ctx, "DKG process returned", z.Any("error", err))
		select {
		case <-parentCtx.Done():
		case dkgErrChan <- err:
		}
	}()

	return cancel
}
