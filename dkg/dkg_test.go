// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
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

	"github.com/obolnetwork/charon/app/eth1wrap"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
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
	"github.com/obolnetwork/charon/testutil/relay"
)

const (
	v1_10 = "v1.10.0"
	v1_9  = "v1.9.0"
	v1_8  = "v1.8.0"
	v1_7  = "v1.7.0"
	v1_6  = "v1.6.0"
	v1_5  = "v1.5.0"
	v1_4  = "v1.4.0"
	v1_3  = "v1.3.0"
	v1_2  = "v1.2.0"
	v1_1  = "v1.1.0"
	v1_0  = "v1.0.0"
)

func isAnyVersion(version string, list ...string) bool {
	for _, v := range list {
		if version == v {
			return true
		}
	}

	return false
}

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

			if isAnyVersion(test.version, v1_0, v1_1, v1_2, v1_3, v1_4, v1_5, v1_6, v1_7, v1_8, v1_9) {
				opts = append(opts, func(d *cluster.Definition) { d.TargetGasLimit = 0 })
			} else {
				opts = append(opts, func(d *cluster.Definition) { d.TargetGasLimit = 30000000 })
			}

			seed := 1
			random := rand.New(rand.NewSource(int64(seed)))
			lock, keys, _ := cluster.NewForT(t, vals, nodes, nodes, seed, random, opts...)
			dir := t.TempDir()

			testDKG(t, lock.Definition, dir, keys, test.keymanager, test.publish, nil)

			if !test.keymanager {
				verifyDKGResults(t, lock.Definition, dir)
			}
		})
	}
}

func TestAppendDKG(t *testing.T) {
	const (
		nodes   = 3
		vals    = 2
		addVals = 3
	)

	withAlgo := func(algo string) func(*cluster.Definition) {
		return func(d *cluster.Definition) {
			d.DKGAlgorithm = algo
		}
	}

	opts := []func(*cluster.Definition){
		withAlgo("default"),
	}

	opts = append(opts, func(d *cluster.Definition) { d.TargetGasLimit = 30000000 })

	seed := 1
	random := rand.New(rand.NewSource(int64(seed)))
	lock, keys, pkShares := cluster.NewForT(t, vals, nodes, nodes, seed, random, opts...)
	srcDir := t.TempDir()

	eth1 := eth1wrap.NewDefaultEthClientRunner("")

	require.NoError(t, lock.Definition.VerifyHashes())
	require.NoError(t, lock.Definition.VerifySignatures(eth1))

	testDKG(t, lock.Definition, srcDir, keys, false, false, nil)
	verifyDKGResults(t, lock.Definition, srcDir)

	dstDir := t.TempDir()

	appendConfigs := make([]dkg.AppendConfig, nodes)
	for i := range nodes {
		secretShares := make([]tbls.PrivateKey, vals)
		for j := range vals {
			secretShares[j] = pkShares[j][i]
		}

		lockCopy := clone(t, lock)

		dataDir := path.Join(srcDir, fmt.Sprintf("node%d", i))
		depositData, err := deposit.ReadDepositDataFiles(dataDir)
		require.NoError(t, err)

		appendConfigs[i] = dkg.AppendConfig{
			AddValidators: addVals,
			ValidatorAddresses: []cluster.ValidatorAddresses{
				{
					FeeRecipientAddress: "0x0000000000000000000000000000000000000001",
					WithdrawalAddress:   "0x0000000000000000000000000000000000000002",
				},
				{
					FeeRecipientAddress: "0x0000000000000000000000000000000000000001",
					WithdrawalAddress:   "0x0000000000000000000000000000000000000002",
				},
				{
					FeeRecipientAddress: "0x0000000000000000000000000000000000000001",
					WithdrawalAddress:   "0x0000000000000000000000000000000000000002",
				},
			},
			ClusterLock:  &lockCopy,
			SecretShares: secretShares,
			DepositData:  depositData,
		}
	}

	testDKG(t, lock.Definition, dstDir, keys, false, false, appendConfigs)

	totalVals := vals + addVals
	secretShares := make([][]tbls.PrivateKey, totalVals)

	for i := range nodes {
		dataDir := path.Join(dstDir, fmt.Sprintf("node%d", i))
		keyFiles, err := keystore.LoadFilesUnordered(path.Join(dataDir, "/validator_keys"))
		require.NoError(t, err)
		require.Len(t, keyFiles, totalVals)

		secrets, err := keyFiles.SequencedKeys()
		require.NoError(t, err)

		for j, secret := range secrets {
			secretShares[j] = append(secretShares[j], secret)
		}

		lockFile, err := os.ReadFile(path.Join(dataDir, "cluster-lock.json"))
		require.NoError(t, err)

		var lock cluster.Lock
		require.NoError(t, json.Unmarshal(lockFile, &lock))
		require.Equal(t, lock.NumValidators, totalVals)
		require.Len(t, lock.Validators, totalVals)

		require.NoError(t, lock.VerifyHashes())

		if !appendConfigs[i].Unverified {
			require.NoError(t, lock.VerifySignatures(eth1wrap.NewDefaultEthClientRunner("")))
		}

		dd, err := deposit.ReadDepositDataFiles(dataDir)
		require.NoError(t, err)
		require.Len(t, dd, 2) // two default amounts: 1eth and 32eth
		require.Len(t, dd[0], totalVals)
		require.Len(t, dd[1], totalVals)
	}
}

func testDKG(t *testing.T, def cluster.Definition, dir string, p2pKeys []*k1.PrivateKey, keymanager bool, publish bool, addConfig []dkg.AppendConfig) {
	t.Helper()

	require.NoError(t, def.VerifySignatures(nil))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start relay.
	relayAddr := relay.StartRelay(ctx, t)

	defClone := clone(t, def)

	// Setup config
	conf := dkg.Config{
		DataDir: dir,
		P2P: p2p.Config{
			Relays: []string{relayAddr},
		},
		Log: log.DefaultConfig(),
		TestConfig: dkg.TestConfig{
			Def: &defClone,
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

	for i := range len(def.Operators) {
		conf := conf
		conf.DataDir = path.Join(dir, fmt.Sprintf("node%d", i))

		conf.P2P.TCPAddrs = []string{testutil.AvailableAddr(t).String()}
		if len(addConfig) > 0 {
			conf.AppendConfig = &addConfig[i]
		}

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
	for i := range len(def.Operators) {
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

func verifyDKGResults(t *testing.T, def cluster.Definition, dir string) {
	t.Helper()

	// Read generated lock and keystores from disk
	var (
		secretShares = make([][]tbls.PrivateKey, def.NumValidators)
		locks        []cluster.Lock
	)
	for i := range len(def.Operators) {
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
		require.NoError(t, lock.VerifySignatures(nil))
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
	for i := range def.NumValidators {
		var sigs []tbls.Signature

		for j := range len(def.Operators) {
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
			if !cluster.SupportPartialDeposits(def.Version) {
				depositAmounts = []eth2p0.Gwei{deposit.DefaultDepositAmount}
			} else {
				depositAmounts = deposit.DefaultDepositAmounts(def.Compounding)
			}
		}

		require.Len(t, val.PartialDepositData, len(depositAmounts))

		// Assert Partial Deposit Data
		uniqueSigs := make(map[string]struct{})

		for i, amount := range depositAmounts {
			pdd := val.PartialDepositData[i]
			require.Equal(t, val.PubKey, pdd.PubKey)
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
		require.Equal(t, val.PubKey, val.BuilderRegistration.Message.PubKey)
		require.Equal(t, registration.DefaultGasLimit, val.BuilderRegistration.Message.GasLimit)

		timestamp, err := eth2util.ForkVersionToGenesisTime(lock.ForkVersion)
		require.NoError(t, err)
		require.Equal(t, timestamp, val.BuilderRegistration.Message.Timestamp)

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

		require.Equal(t,
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
			relayAddr := relay.StartRelay(ctx, t)
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

				if !errors.Is(err, context.Canceled) {
					require.NoError(t, err)
				}

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

	timeout := time.NewTimer(time.Second * 10)
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
	p2pNodeCallback := testutil.NewP2PNodeCallback(t, dkgsync.Protocols()...)

	var configs []dkg.Config
	for i := range len(def.Operators) {
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
				P2PNodeCallback: p2pNodeCallback,
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
		jitter := time.Duration(rand.Intn(300)) * time.Millisecond
		time.Sleep(jitter)

		err := dkg.Run(ctx, config)
		log.Info(ctx, "DKG process returned", z.Any("error", err))

		select {
		case <-parentCtx.Done():
		case dkgErrChan <- err:
		}
	}()

	return cancel
}

func clone[T any](t *testing.T, v T) T {
	t.Helper()

	b, err := json.Marshal(v)
	require.NoError(t, err)

	var clone T

	err = json.Unmarshal(b, &clone)
	require.NoError(t, err)

	return clone
}
