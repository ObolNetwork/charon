// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/eth1wrap"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
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

// testSeed is the default proposer config seed of charon dkg.
var testSeed = proposerconfig.Seed{GasLimit: proposerconfig.DefaultGasLimit, BuilderBoostFactor: proposerconfig.DefaultBuilderBoostFactor}

func isAnyVersion(version string, list ...string) bool {
	return slices.Contains(list, version)
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
		{
			name:    "pedersen",
			dkgAlgo: "pedersen",
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
			} else {
				verifyProposerConfigs(t, dir, len(lock.Operators))
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

	// The existing cluster's signed proposer config carries a builder, a gas limit and a diverging fee recipient.
	const divergingFee = "0x00000000000000000000000000000000000000aa"

	builder := &proposerconfig.Builder{
		MinBid:              "1",
		BuilderBoostFactor:  "90",
		MaxExecutionPayment: "2",
		Builders:            []proposerconfig.BuilderEntry{{URL: "https://builder.example.com"}},
	}

	lockFees := lock.FeeRecipientAddresses()
	cfg, err := proposerconfig.NewConfig(lock, []string{divergingFee, lockFees[1]}, 60_000_000, builder)
	require.NoError(t, err)

	pcDoc := proposerconfig.Document{Version: proposerconfig.Version, LockHash: lock.LockHash, Revision: 2, Config: cfg}
	for i, key := range keys {
		sig, err := proposerconfig.Sign(pcDoc, key)
		require.NoError(t, err)

		pcDoc.Signatures = append(pcDoc.Signatures, proposerconfig.Signature{Operator: i, Signature: sig})
	}

	require.NoError(t, proposerconfig.Verify(pcDoc, lock))

	appendConfigs := make([]dkg.AppendConfig, nodes)
	for i := range nodes {
		pcFile := path.Join(t.TempDir(), "proposer-config.json")
		require.NoError(t, proposerconfig.Write(pcFile, pcDoc, lock, cluster.NodeIdx{PeerIdx: i, ShareIdx: i + 1}))

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
			ClusterLock:        &lockCopy,
			SecretShares:       secretShares,
			DepositData:        depositData,
			ProposerConfigFile: pcFile,
			OverridesFile:      path.Join(t.TempDir(), "absent.json"),
		}
	}

	testDKG(t, lock.Definition, dstDir, keys, false, false, appendConfigs)

	totalVals := vals + addVals
	secretShares := make([][]tbls.PrivateKey, totalVals)

	for i := range nodes {
		dataDir := path.Join(dstDir, fmt.Sprintf("node%d", i))
		secretsDir := path.Join(dataDir, "validator_keys")
		lockPath := path.Join(dataDir, "cluster-lock.json")

		secrets, err := dkg.LoadSecrets(secretsDir)
		require.NoError(t, err)
		require.Len(t, secrets, totalVals)

		for j, secret := range secrets {
			secretShares[j] = append(secretShares[j], secret)
		}

		lock, err := dkg.LoadAndVerifyClusterLock(t.Context(), lockPath, "", false)
		require.NoError(t, err)
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

	// The new lock's proposer config carries the existing config and adds the new validators' fee recipients.
	newFee := "0x0000000000000000000000000000000000000001"

	for _, doc := range verifyProposerConfigs(t, dstDir, nodes) {
		require.Equal(t, "60000000", doc.Config.DefaultConfig.GasLimit)
		require.Equal(t, builder, doc.Config.DefaultConfig.Builder)

		var newLock cluster.Lock

		lockFile, err := os.ReadFile(path.Join(dstDir, "node0", "cluster-lock.json"))
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(lockFile, &newLock))
		require.Equal(t, []string{divergingFee, strings.ToLower(lockFees[1]), newFee, newFee, newFee}, doc.Config.FeeRecipients(newLock))
	}
}

func testDKG(t *testing.T, def cluster.Definition, dir string, p2pKeys []*k1.PrivateKey, keymanager bool, publish bool, addConfig []dkg.AppendConfig) {
	t.Helper()

	require.NoError(t, def.VerifySignatures(nil))

	ctx, cancel := context.WithCancel(t.Context())
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
		ShutdownDelay:      1 * time.Second,
		PublishTimeout:     30 * time.Second,
		Timeout:            8 * time.Second,
		ProposerConfigSeed: testSeed,
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

	// check that the privkey lock file has NOT been deleted in all nodes at the end of dkg
	for i := range len(def.Operators) {
		lockPath := path.Join(dir, fmt.Sprintf("node%d", i), "charon-enr-private-key.lock")

		_, openErr := os.Open(lockPath)
		require.NoError(t, openErr)
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

	docs := verifyProposerConfigs(t, dir, len(def.Operators))
	for i, doc := range docs {
		require.Equal(t, strconv.FormatUint(proposerconfig.DefaultGasLimit, 10), doc.Config.DefaultConfig.GasLimit)
		require.Equal(t, lowerAll(def.FeeRecipientAddresses()), doc.Config.FeeRecipients(locks[i]))
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

	// 	Ensure keystores can generate valid tbls threshold aggregate signature.
	for i := range def.NumValidators {
		sigsByIdx := make(map[int]tbls.Signature)
		msg := []byte("data")

		for j := range len(def.Operators) {
			sig, err := tbls.Sign(secretShares[i][j], msg)
			require.NoError(t, err)

			// Use 1-based share indices as production does
			sigsByIdx[j+1] = sig

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

		// Use ThresholdAggregate (Lagrange interpolation) instead of simple Aggregate
		// to ensure share indices are correct - this is what production uses.
		aSig, err := tbls.ThresholdAggregate(sigsByIdx)
		require.NoError(t, err)

		// Verify against the validator's full public key
		err = tbls.Verify(tbls.PublicKey(locks[0].Validators[i].PubKey), msg, aSig)
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
			connect:    []int{0, 1, 2, 4},
			disconnect: []int{2, 4},
			reconnect:  []int{2, 3, 4},
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

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			ctx = log.WithTopic(ctx, "test")
			relayAddr := relay.StartRelay(ctx, t)
			dir := t.TempDir()
			configs := getConfigs(t, lock.Definition, keys, dir, relayAddr)

			var (
				// Initialise slice with the given number of nodes since this table tests input node indices as testcases.
				stopDkgs   = make([]context.CancelFunc, test.nodes)
				cTracker   = newConnTracker(pIDs)
				dkgErrChan = make(chan error, test.nodes) // Buffered to prevent blocking
				hosts      = make([]host.Host, test.nodes)
			)

			// Set all callbacks before starting any DKG processes to avoid race conditions
			for i := range test.nodes {
				configs[i].TestConfig.SyncCallback = cTracker.Set

				idx := i
				configs[i].TestConfig.P2PNodeCallback = func(h host.Host) {
					hosts[idx] = h
				}
			}

			// Start DKG for initial peers.
			for _, idx := range test.connect {
				log.Info(ctx, "Starting initial peer", z.Int("peer_index", idx))
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

				// Manually close connections from other peers to this peer
				for i, h := range hosts {
					// The hosts array may contain nil values for peers that have been stopped.
					// This safety check ensures we only attempt to close connections for active hosts.
					if h != nil && i != idx {
						_ = h.Network().ClosePeer(pIDs[idx])
					}
				}

				// Wait for this dkg process to return.
				select {
				case err := <-dkgErrChan:
					require.ErrorIs(t, err, context.Canceled)
				case <-time.After(5 * time.Second):
					require.Fail(t, "timeout waiting for peer to stop", "peer_index=%d", idx)
				}

				// Remove the private key lock file so the peer can be restarted.
				_ = os.Remove(p2p.KeyPath(configs[idx].DataDir) + ".lock")
			}

			// Wait for remaining-initial peers to update connection counts.
			expect = len(test.connect) - len(test.disconnect) - 1
			for _, idx := range test.connect {
				if slices.Contains(test.disconnect, idx) {
					continue
				}

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
			for range test.nodes {
				select {
				case err := <-dkgErrChan:
					testutil.SkipIfBindErr(t, err)

					if !errors.Is(err, context.Canceled) {
						require.NoError(t, err)
					}
				case <-time.After(time.Minute):
					require.Fail(t, "timeout waiting for all DKG processes to complete")
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

	timeout := time.NewTimer(time.Second * 20) // Increased timeout for CI environments
	defer timeout.Stop()

	for {
		select {
		case <-timeout.C:
			require.Fail(t, "timeout", "expected %d connections for peer %d, got %d", n, peerIdx, c.count(peerIdx))
		case err := <-dkgErrChan:
			testutil.SkipIfBindErr(t, err)
			// Put error back on channel for other consumers
			select {
			case dkgErrChan <- err:
			default:
				// Channel full, that's ok
			}

			require.Failf(t, "DKG exited unexpectedly", "err=%v", err)
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
			Timeout:            10 * time.Second,
			ProposerConfigSeed: testSeed,
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

func TestZipped(t *testing.T) {
	const (
		nodes = 3
		vals  = 2
	)

	seed := 1
	random := rand.New(rand.NewSource(int64(seed)))
	lock, keys, _ := cluster.NewForT(t, vals, nodes, nodes, seed, random)

	dkgDir := t.TempDir()
	testDKG(t, lock.Definition, dkgDir, keys, false, false, nil)

	// Test bundling only for the first node
	nodeDir := path.Join(dkgDir, "node0")

	// Backup temp dir since bundleOutput is destructive
	backupDir := t.TempDir()
	require.NoError(t, os.CopyFS(backupDir, os.DirFS(nodeDir)))

	err := app.BundleOutput(nodeDir, "dkg.tar.gz")
	require.NoError(t, err, "bundleOutput should succeed for node0")

	// Verify that dkg.tar.gz file exists and original files are deleted
	tarPath := path.Join(nodeDir, "dkg.tar.gz")
	_, err = os.Stat(tarPath)
	require.NoError(t, err, "dkg.tar.gz should exist in node0 directory")

	entries, err := os.ReadDir(nodeDir)
	require.NoError(t, err)

	for _, entry := range entries {
		if entry.Name() != "dkg.tar.gz" {
			t.Errorf("unexpected file %s found in zipped directory", entry.Name())
		}
	}

	// Create new temp dir and unzip to there
	unzippedDir := t.TempDir()
	err = app.ExtractArchive(tarPath, unzippedDir)
	require.NoError(t, err)

	// Compare backup with unzipped folder
	err = app.CompareDirectories(backupDir, unzippedDir)
	require.NoError(t, err, "unzipped content should match original for node0")
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

// verifyProposerConfigs asserts each node wrote a revision 1 proposer config signed by all operators of its
// lock, identical across nodes, and returns the documents in node order.
func verifyProposerConfigs(t *testing.T, dir string, nodes int) []proposerconfig.Document {
	t.Helper()

	var docs []proposerconfig.Document

	for i := range nodes {
		dataDir := path.Join(dir, fmt.Sprintf("node%d", i))

		lockFile, err := os.ReadFile(path.Join(dataDir, "cluster-lock.json"))
		require.NoError(t, err)

		var lock cluster.Lock
		require.NoError(t, json.Unmarshal(lockFile, &lock))

		doc, err := proposerconfig.Load(path.Join(dataDir, "vc-config", "proposer-config.json"), lock, cluster.NodeIdx{PeerIdx: i, ShareIdx: i + 1})
		require.NoError(t, err)
		require.NoError(t, proposerconfig.Verify(doc, lock))
		require.EqualValues(t, 1, doc.Revision)
		require.Len(t, doc.Signatures, nodes)

		for j, sig := range doc.Signatures {
			require.Equal(t, j, sig.Operator)
		}

		docs = append(docs, doc)
	}

	for _, doc := range docs[1:] {
		h0, err := docs[0].Hash()
		require.NoError(t, err)
		h, err := doc.Hash()
		require.NoError(t, err)
		require.Equal(t, h0, h)
	}

	return docs
}

func lowerAll(addrs []string) []string {
	res := make([]string, 0, len(addrs))
	for _, a := range addrs {
		res = append(res, strings.ToLower(a))
	}

	return res
}

// runMismatchedNodes runs dkg.Run on all nodes of lock, letting mutate change each node's config, and returns
// each node's error. Every node must fail before key generation.
func runMismatchedNodes(t *testing.T, lock cluster.Lock, keys []*k1.PrivateKey, mutate func(i int, conf *dkg.Config)) []error {
	t.Helper()

	nodes := len(lock.Operators)
	dir := t.TempDir()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	relayAddr := relay.StartRelay(ctx, t)

	errs := make([]error, nodes)

	var eg errgroup.Group

	for i := range nodes {
		def := clone(t, lock.Definition)
		conf := dkg.Config{
			DataDir: path.Join(dir, fmt.Sprintf("node%d", i)),
			P2P: p2p.Config{
				Relays:   []string{relayAddr},
				TCPAddrs: []string{testutil.AvailableAddr(t).String()},
			},
			Log: log.DefaultConfig(),
			TestConfig: dkg.TestConfig{
				Def: &def,
				StoreKeysFunc: func(secrets []tbls.PrivateKey, dir string) error {
					return keystore.StoreKeysInsecure(secrets, dir, keystore.ConfirmInsecureKeys)
				},
				SyncOpts: []func(*dkgsync.Client){dkgsync.WithPeriod(time.Millisecond * 50)},
			},
			ShutdownDelay:      time.Second,
			Timeout:            8 * time.Second,
			ProposerConfigSeed: testSeed,
		}
		mutate(i, &conf)

		require.NoError(t, os.MkdirAll(conf.DataDir, 0o755))
		require.NoError(t, k1util.Save(keys[i], p2p.KeyPath(conf.DataDir)))

		eg.Go(func() error {
			errs[i] = dkg.Run(peerCtx(ctx, i), conf)
			return nil
		})
	}

	require.NoError(t, eg.Wait())

	for i, err := range errs {
		testutil.SkipIfBindErr(t, err)

		// Fails before key generation: nothing written.
		_, statErr := os.Stat(path.Join(dir, fmt.Sprintf("node%d", i), "validator_keys"))
		require.ErrorIs(t, statErr, os.ErrNotExist)
	}

	return errs
}

func TestDKGSeedMismatch(t *testing.T) {
	random := rand.New(rand.NewSource(1))
	lock, keys, _ := cluster.NewForT(t, 2, 3, 3, 1, random)

	errs := runMismatchedNodes(t, lock, keys, func(i int, conf *dkg.Config) {
		if i == 2 {
			conf.ProposerConfigSeed.GasLimit = 60_000_000
		}
	})

	for i, err := range errs {
		require.ErrorContains(t, err, "default.gas_limit: 200000000 -> 60000000", "node %d", i)
		require.ErrorContains(t, err, "--proposer-config-*", "node %d", i)
	}
}

func TestAppendDKGMismatch(t *testing.T) {
	random := rand.New(rand.NewSource(1))
	lock, keys, pkShares := cluster.NewForT(t, 2, 3, 3, 1, random)

	errs := runMismatchedNodes(t, lock, keys, func(i int, conf *dkg.Config) {
		gasLimit := proposerconfig.DefaultGasLimit
		if i == 2 {
			gasLimit = 60_000_000
		}

		cfg, err := proposerconfig.NewConfig(lock, lock.FeeRecipientAddresses(), gasLimit, nil)
		require.NoError(t, err)

		// Unsigned revision 0 files may differ between nodes.
		pcFile := path.Join(t.TempDir(), "proposer-config.json")
		doc := proposerconfig.Document{Version: proposerconfig.Version, LockHash: lock.LockHash, Config: cfg}
		require.NoError(t, proposerconfig.Write(pcFile, doc, lock, cluster.NodeIdx{PeerIdx: i, ShareIdx: i + 1}))

		lockCopy := clone(t, lock)
		conf.AppendConfig = &dkg.AppendConfig{
			ClusterLock:        &lockCopy,
			SecretShares:       []tbls.PrivateKey{pkShares[0][i], pkShares[1][i]},
			AddValidators:      1,
			ValidatorAddresses: []cluster.ValidatorAddresses{{FeeRecipientAddress: lock.FeeRecipientAddresses()[0], WithdrawalAddress: lock.WithdrawalAddresses()[0]}},
			ProposerConfigFile: pcFile,
		}
	})

	for i, err := range errs {
		require.ErrorContains(t, err, "default.gas_limit: 200000000 -> 60000000", "node %d", i)
		require.ErrorContains(t, err, "charon alpha edit proposer-config", "node %d", i)
	}
}

func TestDKGInvalidInputs(t *testing.T) {
	const badChecksum = "0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed" // EIP-55 is 0x5aAeb6...

	tests := []struct {
		name    string
		mutate  func(*dkg.Config)
		errMsg  string
		address string
	}{
		{
			name: "bad fee recipient checksum",
			mutate: func(conf *dkg.Config) {
				conf.TestConfig.Def.ValidatorAddresses[1].FeeRecipientAddress = badChecksum
			},
			errMsg:  "invalid fee recipient address",
			address: badChecksum,
		},
		{
			name: "zero gas limit seed",
			mutate: func(conf *dkg.Config) {
				conf.ProposerConfigSeed.GasLimit = 0
			},
			errMsg: "proposer-config-gas-limit must be greater than 0",
		},
		{
			name: "builder value without urls",
			mutate: func(conf *dkg.Config) {
				conf.ProposerConfigSeed.BuilderBoostFactor = 90
				conf.ProposerConfigSeed.NonDefault = []string{"proposer-config-builder-boost-factor"}
			},
			errMsg: "require proposer-config-builder-urls",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			random := rand.New(rand.NewSource(1))
			lock, keys, _ := cluster.NewForT(t, 2, 3, 3, 1, random)
			dir := t.TempDir()
			def := clone(t, lock.Definition)

			conf := dkg.Config{
				DataDir: dir,
				P2P:     p2p.Config{TCPAddrs: []string{testutil.AvailableAddr(t).String()}},
				Log:     log.DefaultConfig(),
				TestConfig: dkg.TestConfig{
					Def: &def,
					StoreKeysFunc: func(secrets []tbls.PrivateKey, dir string) error {
						return keystore.StoreKeysInsecure(secrets, dir, keystore.ConfirmInsecureKeys)
					},
				},
				Timeout:            8 * time.Second,
				ProposerConfigSeed: testSeed,
			}
			test.mutate(&conf)
			require.NoError(t, k1util.Save(keys[0], p2p.KeyPath(dir)))

			// A single node: it must fail before waiting for peers, which would time out.
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()

			err := dkg.Run(ctx, conf)
			testutil.SkipIfBindErr(t, err)
			require.ErrorContains(t, err, test.errMsg)

			if test.address != "" {
				require.Contains(t, fieldStrings(err), test.address)
			}

			_, statErr := os.Stat(path.Join(dir, "validator_keys"))
			require.ErrorIs(t, statErr, os.ErrNotExist)
		})
	}
}

// fieldStrings returns the string values of the structured error's fields.
func fieldStrings(err error) []string {
	var res []string

	for _, field := range z.Fields(err) {
		field(func(f zap.Field) { res = append(res, f.String) })
	}

	return res
}
