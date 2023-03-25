// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cmd/relay"
	"github.com/obolnetwork/charon/dkg"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/p2p"
	tblsv2 "github.com/obolnetwork/charon/tbls/v2"
	tblsconv2 "github.com/obolnetwork/charon/tbls/v2/tblsconv"
	"github.com/obolnetwork/charon/testutil"
)

func TestMain(m *testing.M) {
	tblsv2.SetImplementation(tblsv2.Herumi{})
	os.Exit(m.Run())
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

	tests := []struct {
		name       string
		dkgAlgo    string
		keymanager bool
		publish    bool
	}{
		{
			name:    "keycast",
			dkgAlgo: "keycast",
		},
		{
			name:    "frost",
			dkgAlgo: "frost",
		},
		{
			name:       "dkg with keymanager",
			dkgAlgo:    "keycast",
			keymanager: true,
		},
		{
			name:    "dkg with lockfile publish",
			dkgAlgo: "keycast",
			publish: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			version := cluster.WithVersion("v1.6.0") // TODO(corver): Remove this once v1.6 is released.
			lock, keys, _ := cluster.NewForT(t, vals, nodes, nodes, 1, withAlgo(test.dkgAlgo), version)
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
	relayAddr, errChan := startRelay(ctx, t)

	// Setup config
	conf := dkg.Config{
		DataDir: dir,
		P2P: p2p.Config{
			Relays: []string{relayAddr},
		},
		Log:     log.DefaultConfig(),
		TestDef: &def,
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
			err := dkg.Run(ctx, conf)
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

	runChan := make(chan error, 1)
	go func() {
		runChan <- eg.Wait()
	}()

	select {
	case err := <-errChan:
		// If this returns first, something went wrong with the relay and the test will fail.
		cancel()
		testutil.SkipIfBindErr(t, err)
		require.Fail(t, "bootnode error:", err)
	case err := <-runChan:
		cancel()
		testutil.SkipIfBindErr(t, err)
		require.NoError(t, err)
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

// startRelay starts a charon relay and returns its http endpoint.
func startRelay(ctx context.Context, t *testing.T) (string, <-chan error) {
	t.Helper()

	dir := t.TempDir()

	addr := testutil.AvailableAddr(t).String()

	errChan := make(chan error, 1)
	go func() {
		errChan <- relay.Run(ctx, relay.Config{
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
	}()

	endpoint := "http://" + addr

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

func verifyDKGResults(t *testing.T, def cluster.Definition, dir string) {
	t.Helper()

	// Read generated lock and keystores from disk
	var (
		secretShares = make([][]tblsv2.PrivateKey, def.NumValidators)
		locks        []cluster.Lock
	)
	for i := 0; i < len(def.Operators); i++ {
		dataDir := path.Join(dir, fmt.Sprintf("node%d", i))
		keyShares, err := keystore.LoadKeys(path.Join(dataDir, "/validator_keys"))
		require.NoError(t, err)
		require.Len(t, keyShares, def.NumValidators)

		for i, key := range keyShares {
			secretShares[i] = append(secretShares[i], key)
		}

		lockFile, err := os.ReadFile(path.Join(dataDir, "cluster-lock.json"))
		require.NoError(t, err)

		var lock cluster.Lock
		require.NoError(t, json.Unmarshal(lockFile, &lock))
		require.NoError(t, lock.VerifySignatures())
		locks = append(locks, lock)

		for _, val := range lock.Validators {
			require.EqualValues(t, val.PubKey, val.DepositData.PubKey)
			require.EqualValues(t, 32_000_000_000, val.DepositData.Amount)
		}
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
		var sigs []tblsv2.Signature
		for j := 0; j < len(def.Operators); j++ {
			msg := []byte("data")
			sig, err := tblsv2.Sign(secretShares[i][j], msg)
			require.NoError(t, err)
			sigs = append(sigs, sig)

			// Ensure all public shares can verify the partial signature
			for _, lock := range locks {
				if len(lock.Validators[i].PubShares) == 0 {
					continue
				}
				pk, err := tblsconv2.PubkeyFromBytes(lock.Validators[i].PubShares[j])
				require.NoError(t, err)
				err = tblsv2.Verify(pk, msg, sig)
				require.NoError(t, err)
			}
		}
		_, err := tblsv2.Aggregate(sigs)
		require.NoError(t, err)
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
			version := cluster.WithVersion("v1.6.0") // TODO(corver): remove this once v1.6 released.
			lock, keys, _ := cluster.NewForT(t, test.vals, test.nodes, test.nodes, 0, version)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Start bootnode.
			bnode, errChan := startRelay(ctx, t)

			dir := t.TempDir()

			configs := getConfigs(t, lock.Definition, keys, dir, bnode)

			// Initialise slice with the given number of nodes since this table tests input node indices as testcases.
			stopDkgs := make([]context.CancelFunc, test.nodes)

			var (
				done       = make(chan struct{})
				dkgErrChan = make(chan error)
			)

			newCallback := func(required int) func(int, peer.ID) {
				var called bool
				return func(connected int, id peer.ID) {
					if called || connected != required {
						return
					}

					called = true
					done <- struct{}{}
				}
			}

			// Start DKG for initial peers.
			for _, idx := range test.connect {
				configs[idx].TestSyncCallback = newCallback(len(test.connect) - 1)
				stopDkgs[idx] = startNewDKG(t, ctx, configs[idx], dkgErrChan)
			}

			// Wait for initial peers to connect with each other.
			var connectedCount int
			for connectedCount != len(test.connect) {
				select {
				case <-done:
					connectedCount++
				case err := <-errChan:
					cancel()
					testutil.SkipIfBindErr(t, err)
					require.Fail(t, fmt.Sprintf("bootnode error: %v", err))
				case err := <-dkgErrChan:
					cancel()
					testutil.SkipIfBindErr(t, err)
					require.Fail(t, fmt.Sprintf("dkg error: %v", err))
				}
			}

			// Drop some peers.
			for _, idx := range test.disconnect {
				stopDkgs[idx]()

				// Wait for this dkg process to return.
				err := <-dkgErrChan
				require.ErrorIs(t, err, context.Canceled)
			}

			// Start remaining peers.
			for _, idx := range test.reconnect {
				stopDkgs[idx] = startNewDKG(t, ctx, configs[idx], dkgErrChan)
			}

			// Assert DKG results for all DKG processes.
			var disconnectedCount int
			for disconnectedCount != test.nodes {
				select {
				case err := <-errChan:
					cancel()
					testutil.SkipIfBindErr(t, err)
					require.Fail(t, fmt.Sprintf("bootnode error: %v", err))
				case err := <-dkgErrChan:
					testutil.SkipIfBindErr(t, err)
					require.NoError(t, err)
					disconnectedCount++
				}
			}

			verifyDKGResults(t, lock.Definition, dir)
		})
	}
}

func getConfigs(t *testing.T, def cluster.Definition, keys []*k1.PrivateKey, dir, bootnode string) []dkg.Config {
	t.Helper()

	var configs []dkg.Config
	for i := 0; i < len(def.Operators); i++ {
		conf := dkg.Config{
			DataDir: path.Join(dir, fmt.Sprintf("node%d", i)),
			P2P: p2p.Config{
				Relays:   []string{bootnode},
				TCPAddrs: []string{testutil.AvailableAddr(t).String()},
			},
			Log:     log.DefaultConfig(),
			TestDef: &def,
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
		select {
		case <-parentCtx.Done():
			return
		case dkgErrChan <- err:
		}
	}()

	return cancel
}
