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

package cmd

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/stretchr/testify/require"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -run=TestCreateCluster -update -clean

func TestCreateCluster(t *testing.T) {
	defPath := "../cluster/examples/cluster-definition-002.json"
	def, err := loadDefinition(context.Background(), defPath)
	require.NoError(t, err)

	// Serve definition over network
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defBytes, err := os.ReadFile(defPath)
		require.NoError(t, err)

		_, err = w.Write(defBytes)
		require.NoError(t, err)
	}))
	defer srv.Close()

	tests := []struct {
		Name   string
		Config clusterConfig
		Prep   func(*testing.T, clusterConfig) clusterConfig
	}{
		{
			Name: "simnet",
			Config: clusterConfig{
				NumNodes:  4,
				Threshold: 3,
				NumDVs:    1,
			},
		},
		{
			Name: "splitkeys",
			Config: clusterConfig{
				NumNodes:  4,
				Threshold: 3,
				NumDVs:    2,
				SplitKeys: true,
			},
			Prep: func(t *testing.T, config clusterConfig) clusterConfig {
				t.Helper()

				keyDir := t.TempDir()

				_, secret1, err := tbls.Keygen()
				require.NoError(t, err)
				_, secret2, err := tbls.Keygen()
				require.NoError(t, err)

				err = keystore.StoreKeys([]*bls_sig.SecretKey{secret1, secret2}, keyDir)
				require.NoError(t, err)

				config.SplitKeysDir = keyDir

				return config
			},
		},
		{
			Name: "goerli",
			Config: clusterConfig{
				NumNodes:  minNodes,
				Threshold: 3,
				NumDVs:    2,
				Network:   "goerli",
			},
		},
		{
			Name: "solo flow definition from disk",
			Config: clusterConfig{
				DefFile: defPath,
			},
		},
		{
			Name: "solo flow definition from network",
			Config: clusterConfig{
				DefFile: srv.URL,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			if test.Prep != nil {
				test.Config = test.Prep(t, test.Config)
			}

			test.Config.WithdrawalAddr = defaultWithdrawalAddr

			if test.Config.Network == "" {
				test.Config.Network = defaultNetwork
			}

			testCreateCluster(t, test.Config, def)
		})
	}
}

func testCreateCluster(t *testing.T, conf clusterConfig, def cluster.Definition) {
	t.Helper()

	dir := t.TempDir()
	conf.ClusterDir = dir
	conf.Name = t.Name()

	var buf bytes.Buffer
	err := runCreateCluster(context.Background(), &buf, conf)
	if err != nil {
		log.Error(context.Background(), "", err)
	}
	require.NoError(t, err)

	t.Run("output", func(t *testing.T) {
		out := bytes.ReplaceAll(buf.Bytes(), []byte(dir), []byte("charon"))
		testutil.RequireGoldenBytes(t, out)
	})

	t.Run("files", func(t *testing.T) {
		l1files, err := filepath.Glob(path.Join(dir, "*"))
		require.NoError(t, err)
		l2files, err := filepath.Glob(path.Join(dir, "*/*"))
		require.NoError(t, err)

		var files []string
		for _, file := range append(l1files, l2files...) {
			files = append(files, strings.TrimPrefix(file, dir+"/"))
		}

		testutil.RequireGoldenJSON(t, files)
	})

	t.Run("valid lock", func(t *testing.T) {
		// Since `cluster-lock.json` is copied into each node directory, use any one of them.
		b, err := os.ReadFile(path.Join(nodeDir(conf.ClusterDir, 0), "cluster-lock.json"))
		require.NoError(t, err)

		var lock cluster.Lock
		require.NoError(t, json.Unmarshal(b, &lock))
		require.NoError(t, lock.VerifyHashes())
		require.NoError(t, lock.VerifySignatures())

		if conf.DefFile != "" {
			// Config hash and creator should remain the same
			require.Equal(t, def.ConfigHash, lock.ConfigHash)
			require.Equal(t, def.Creator, lock.Creator)

			for i := 0; i < len(def.Operators); i++ {
				// ENRs should be populated
				require.NotEqual(t, lock.Operators[i].ENR, "")
			}
		}
	})
}

func TestValidateDef(t *testing.T) {
	ctx := context.Background()
	conf := clusterConfig{
		Name:           "test",
		NumNodes:       4,
		NumDVs:         4,
		Threshold:      3,
		WithdrawalAddr: "0x0000000000000000000000000000000000000000",
		Network:        "goerli",
	}

	definition, err := newDefFromConfig(ctx, conf)
	require.NoError(t, err)

	t.Run("zero address", func(t *testing.T) {
		def := definition
		gnosis, err := hex.DecodeString(strings.TrimPrefix(eth2util.Gnosis.ForkVersionHex, "0x"))
		require.NoError(t, err)
		def.ForkVersion = gnosis

		err = validateDef(ctx, false, conf.KeymanagerAddrs, def)
		require.Error(t, err, "zero address")
	})

	t.Run("fork versions", func(t *testing.T) {
		def := definition
		err = validateDef(ctx, false, conf.KeymanagerAddrs, def)
		require.NoError(t, err)

		mainnet, err := hex.DecodeString(strings.TrimPrefix(eth2util.Mainnet.ForkVersionHex, "0x"))
		require.NoError(t, err)
		def.ForkVersion = mainnet

		err = validateDef(ctx, conf.InsecureKeys, conf.KeymanagerAddrs, def)
		require.Error(t, err, "zero address")
	})

	t.Run("insufficient keymanager addresses", func(t *testing.T) {
		conf := conf
		conf.KeymanagerAddrs = []string{"127.0.0.1:1234"}

		err = validateDef(ctx, true, conf.KeymanagerAddrs, definition)
		require.Error(t, err)
	})

	t.Run("insecure keys", func(t *testing.T) {
		conf := conf
		err = validateDef(ctx, true, conf.KeymanagerAddrs, definition) // Validate with insecure keys set to true
		require.NoError(t, err)
	})

	t.Run("insufficient number of nodes", func(t *testing.T) {
		def := definition
		def.Operators = nil
		err = validateDef(ctx, conf.InsecureKeys, conf.KeymanagerAddrs, def)
		require.ErrorContains(t, err, "insufficient number of nodes")
	})

	t.Run("name not provided", func(t *testing.T) {
		def := definition
		def.Name = ""
		err = validateDef(ctx, conf.InsecureKeys, conf.KeymanagerAddrs, def)
		require.ErrorContains(t, err, "name not provided")
	})
}

// TestKeymanager tests keymanager support by letting create cluster command split a single secret and then receiving those keyshares using test
// keymanager servers. These shares are then combined to create the combined share which is then compared to the original secret that was split.
func TestKeymanager(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create secret
	_, secret1, err := tbls.Keygen()
	require.NoError(t, err)
	originalSecret, err := secret1.MarshalBinary()
	require.NoError(t, err)

	// Store secret
	keyDir := t.TempDir()
	err = keystore.StoreKeys([]*bls_sig.SecretKey{secret1}, keyDir)
	require.NoError(t, err)

	// Create minNodes test servers
	results := make(chan result, minNodes) // Buffered channel
	defer close(results)

	var addrs []string
	var servers []*httptest.Server
	for i := 0; i < minNodes; i++ {
		srv := httptest.NewServer(newKeymanagerHandler(ctx, t, i, results))
		servers = append(servers, srv)
		addrs = append(addrs, srv.URL)
	}

	defer func() {
		for _, srv := range servers {
			srv.Close()
		}
	}()

	// Create cluster config
	conf := clusterConfig{
		Name:            t.Name(),
		SplitKeysDir:    keyDir,
		SplitKeys:       true,
		NumNodes:        minNodes,
		NumDVs:          1,
		KeymanagerAddrs: addrs,
		Network:         defaultNetwork,
		WithdrawalAddr:  defaultWithdrawalAddr,
		Clean:           true,
	}
	conf.ClusterDir = t.TempDir()

	t.Run("all successful", func(t *testing.T) {
		// Run create cluster command
		var buf bytes.Buffer
		err = runCreateCluster(context.Background(), &buf, conf)
		if err != nil {
			log.Error(context.Background(), "", err)
		}
		require.NoError(t, err)

		// Receive secret shares from all keymanager servers
		var shares []*bls_sig.SecretKeyShare
		for len(shares) < minNodes {
			res := <-results
			secretBin, err := res.secret.MarshalBinary()
			require.NoError(t, err)

			share := new(bls_sig.SecretKeyShare)
			err = share.UnmarshalBinary(append(secretBin, byte(res.id+1)))
			require.NoError(t, err)

			shares = append(shares, share)
		}

		// Combine the shares and test equality with original share
		csb, err := tbls.CombineShares(shares, 3, minNodes)
		require.NoError(t, err)
		combinedSecret, err := csb.MarshalBinary()
		require.NoError(t, err)

		require.Equal(t, combinedSecret, originalSecret)
	})

	t.Run("some unsuccessful", func(t *testing.T) {
		// Close one server so that request to it fails
		servers[0].Close()

		// Run create cluster command
		var buf bytes.Buffer
		err = runCreateCluster(context.Background(), &buf, conf)
		if err != nil {
			log.Error(context.Background(), "", err)
		}
		require.ErrorContains(t, err, "cannot ping address")
	})
}

// mockKeymanagerReq is a mock keymanager request for use in tests.
type mockKeymanagerReq struct {
	Keystores []keystore.Keystore `json:"keystores"`
	Passwords []string            `json:"passwords"`
}

// decrypt returns the secret from the encrypted keystore.
func decrypt(t *testing.T, store keystore.Keystore, password string) (*bls_sig.SecretKey, error) {
	t.Helper()

	decryptor := keystorev4.New()
	secretBytes, err := decryptor.Decrypt(store.Crypto, password)
	require.NoError(t, err)

	return tblsconv.SecretFromBytes(secretBytes)
}

// result is a struct for receiving secrets along with their id.
// This is needed as tbls.CombineShares needs shares in the correct (original) order.
type result struct {
	id     int
	secret *bls_sig.SecretKey
}

// newKeymanagerHandler returns http handler for a test keymanager API server.
func newKeymanagerHandler(ctx context.Context, t *testing.T, id int, results chan<- result) http.Handler {
	t.Helper()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		defer r.Body.Close()

		var req mockKeymanagerReq
		require.NoError(t, json.Unmarshal(data, &req))

		require.Equal(t, len(req.Keystores), len(req.Passwords))
		require.Equal(t, len(req.Keystores), 1) // Since we split only 1 key

		secret, err := decrypt(t, req.Keystores[0], req.Passwords[0])
		require.NoError(t, err)

		res := result{
			id:     id,
			secret: secret,
		}

		w.WriteHeader(http.StatusOK)

		select {
		case <-ctx.Done():
			return
		case results <- res:
		}
	})
}
