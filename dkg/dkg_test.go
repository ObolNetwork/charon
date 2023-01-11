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

package dkg_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"testing"
	"time"

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cmd/relay"
	"github.com/obolnetwork/charon/dkg"
	"github.com/obolnetwork/charon/eth2util/keystore"
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

	t.Run("keycast", func(t *testing.T) {
		lock, keys, _ := cluster.NewForT(t, vals, nodes, nodes, 0, withAlgo("keycast"))
		testDKG(t, lock.Definition, keys)
	})

	t.Run("frost", func(t *testing.T) {
		lock, keys, _ := cluster.NewForT(t, vals, nodes, nodes, 0, withAlgo("frost"))
		testDKG(t, lock.Definition, keys)
	})
}

func testDKG(t *testing.T, def cluster.Definition, p2pKeys []*ecdsa.PrivateKey) {
	t.Helper()

	require.NoError(t, def.VerifySignatures())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start bootnode.
	bnode, errChan := startBootnode(ctx, t)

	// Setup
	dir, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	conf := dkg.Config{
		DataDir: dir,
		P2P: p2p.Config{
			UDPBootnodes: []string{bnode},
		},
		Log:     log.DefaultConfig(),
		TestDef: &def,
	}

	// Run dkg for each node
	var eg errgroup.Group
	for i := 0; i < len(def.Operators); i++ {
		conf := conf
		conf.DataDir = path.Join(dir, fmt.Sprintf("node%d", i))
		conf.P2P.TCPAddrs = []string{testutil.AvailableAddr(t).String()}
		conf.P2P.UDPAddr = testutil.AvailableAddr(t).String()

		require.NoError(t, os.MkdirAll(conf.DataDir, 0o755))
		err := crypto.SaveECDSA(p2p.KeyPath(conf.DataDir), p2pKeys[i])
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
		// If this returns first, something went wrong with the bootnode and the test will fail.
		cancel()
		testutil.SkipIfBindErr(t, err)
		require.Fail(t, "bootnode error: %v", err)
	case err := <-runChan:
		cancel()
		testutil.SkipIfBindErr(t, err)
		require.NoError(t, err)
	}

	verifyDKGResults(t, def, dir)
}

// startBootnode starts a charon bootnode and returns its http ENR endpoint.
func startBootnode(ctx context.Context, t *testing.T) (string, <-chan error) {
	t.Helper()

	dir, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	addr := testutil.AvailableAddr(t).String()

	errChan := make(chan error, 1)
	go func() {
		errChan <- relay.Run(ctx, relay.Config{
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
			MaxConns:   1024,
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

func verifyDKGResults(t *testing.T, def cluster.Definition, dir string) {
	t.Helper()

	// Read generated lock and keystores from disk
	var (
		secretShares = make([][]*bls_sig.SecretKey, def.NumValidators)
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
		var sigs []*bls_sig.PartialSignature
		for j := 0; j < len(def.Operators); j++ {
			msg := []byte("data")
			sig, err := tbls.Sign(secretShares[i][j], msg)
			require.NoError(t, err)
			sigs = append(sigs, &bls_sig.PartialSignature{
				Identifier: byte(j),
				Signature:  sig.Value,
			})

			// Ensure all public shares can verify the partial signature
			for _, lock := range locks {
				if len(lock.Validators[i].PubShares) == 0 {
					continue
				}
				pk, err := tblsconv.KeyFromBytes(lock.Validators[i].PubShares[j])
				require.NoError(t, err)
				ok, err := tbls.Verify(pk, msg, sig)
				require.NoError(t, err)
				require.True(t, ok)
			}
		}
		_, err := tbls.Aggregate(sigs)
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
			lock, keys, _ := cluster.NewForT(t, test.vals, test.nodes, test.nodes, 0)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Start bootnode.
			bnode, errChan := startBootnode(ctx, t)

			dir, err := os.MkdirTemp("", "")
			require.NoError(t, err)

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
				case err = <-errChan:
					cancel()
					testutil.SkipIfBindErr(t, err)
					require.Fail(t, fmt.Sprintf("bootnode error: %v", err))
				case err = <-dkgErrChan:
					cancel()
					testutil.SkipIfBindErr(t, err)
					require.Fail(t, fmt.Sprintf("dkg error: %v", err))
				}
			}

			// Drop some peers.
			for _, idx := range test.disconnect {
				stopDkgs[idx]()

				// Wait for this dkg process to return.
				err = <-dkgErrChan
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
				case err = <-errChan:
					cancel()
					testutil.SkipIfBindErr(t, err)
					require.Fail(t, fmt.Sprintf("bootnode error: %v", err))
				case err = <-dkgErrChan:
					testutil.SkipIfBindErr(t, err)
					require.NoError(t, err)
					disconnectedCount++
				}
			}

			verifyDKGResults(t, lock.Definition, dir)
		})
	}
}

func getConfigs(t *testing.T, def cluster.Definition, keys []*ecdsa.PrivateKey, dir, bootnode string) []dkg.Config {
	t.Helper()

	var configs []dkg.Config
	for i := 0; i < len(def.Operators); i++ {
		conf := dkg.Config{
			DataDir: path.Join(dir, fmt.Sprintf("node%d", i)),
			P2P: p2p.Config{
				UDPBootnodes: []string{bootnode},
				TCPAddrs:     []string{testutil.AvailableAddr(t).String()},
				UDPAddr:      testutil.AvailableAddr(t).String(),
			},
			Log:     log.DefaultConfig(),
			TestDef: &def,
		}
		require.NoError(t, os.MkdirAll(conf.DataDir, 0o755))

		err := crypto.SaveECDSA(p2p.KeyPath(conf.DataDir), keys[i])
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
