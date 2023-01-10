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
	"encoding/json"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -run=TestCreateCluster -update -clean

func TestCreateCluster(t *testing.T) {
	def := newDefinition(t, "solo flow definition")
	defBytes, err := def.MarshalJSON()
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		}, {
			Name: "splitkeys",
			Config: clusterConfig{
				NumNodes:  4,
				Threshold: 3,
				NumDVs:    1,
				SplitKeys: true,
			},
			Prep: func(t *testing.T, config clusterConfig) clusterConfig {
				t.Helper()

				keyDir, err := os.MkdirTemp("", "")
				require.NoError(t, err)

				_, secret1, err := tbls.Keygen()
				require.NoError(t, err)
				_, secret2, err := tbls.Keygen()
				require.NoError(t, err)

				err = keystore.StoreKeys([]*bls_sig.SecretKey{secret1, secret2}, keyDir)
				require.NoError(t, err)

				config.SplitKeysDir = keyDir

				return config
			},
		}, {
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
			Prep: func(t *testing.T, config clusterConfig) clusterConfig {
				t.Helper()

				// Save definition to disk
				dir, err := os.MkdirTemp("", "")
				require.NoError(t, err)
				defPath := path.Join(dir, "cluster-definition.json")

				err = os.WriteFile(defPath, defBytes, 0o444)
				require.NoError(t, err)
				config.DefFile = defPath

				return config
			},
		},
		{
			Name: "solo flow definition from network",
			Prep: func(t *testing.T, config clusterConfig) clusterConfig {
				t.Helper()
				config.DefFile = srv.URL

				return config
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

			testCreateCluster(t, test.Config)
		})
	}
}

func testCreateCluster(t *testing.T, conf clusterConfig) {
	t.Helper()

	dir, err := os.MkdirTemp("", "")
	require.NoError(t, err)
	conf.ClusterDir = dir
	conf.Name = t.Name()

	var buf bytes.Buffer
	err = runCreateCluster(context.Background(), &buf, conf)
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
			var def cluster.Definition
			def, err = loadDefinition(context.Background(), conf.DefFile)
			require.NoError(t, err)

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

func TestChecksumAddr(t *testing.T) {
	expected := "0xC0404ed740a69d11201f5eD297c5732F562c6E4e"
	got, err := checksumAddr(expected)
	require.NoError(t, err)
	require.Equal(t, got, expected)

	expected = "0x32F562c6E4eexyzXYZ69d11201f5eD297c57C0404"
	_, err = checksumAddr(expected)
	require.Error(t, err, "invalid address")
}

func TestValidNetwork(t *testing.T) {
	ctx := context.Background()

	conf := clusterConfig{
		Name:           "test",
		NumNodes:       4,
		Threshold:      3,
		WithdrawalAddr: "0x0000000000000000000000000000000000000000",
		Network:        "gnosis",
	}
	err := validateClusterConfig(ctx, conf.InsecureKeys, conf.NumNodes, conf.Name, conf.WithdrawalAddr, conf.Network)
	require.Error(t, err, "zero address")

	conf.Network = "goerli"
	err = validateClusterConfig(ctx, conf.InsecureKeys, conf.NumNodes, conf.Name, conf.WithdrawalAddr, conf.Network)
	require.NoError(t, err)

	conf.InsecureKeys = true

	err = validateClusterConfig(ctx, conf.InsecureKeys, conf.NumNodes, conf.Name, conf.WithdrawalAddr, conf.Network)
	require.NoError(t, err)

	conf.Network = "mainnet"
	err = validateClusterConfig(ctx, conf.InsecureKeys, conf.NumNodes, conf.Name, conf.WithdrawalAddr, conf.Network)
	require.Error(t, err, "zero address")
}

// newDefinition returns a new definition with creator field populated.
func newDefinition(t *testing.T, clusterName string) cluster.Definition {
	t.Helper()

	// Construct the creator
	secret, err := crypto.GenerateKey()
	require.NoError(t, err)

	addr := crypto.PubkeyToAddress(secret.PublicKey)
	creator := cluster.Creator{
		Address: addr.Hex(),
	}

	// Construct the definition
	ops := []cluster.Operator{{}, {}, {}, {}}
	def, err := cluster.NewDefinition(clusterName, 1, 3,
		"", "", eth2util.Sepolia.ForkVersionHex, creator, ops, rand.New(rand.NewSource(1)))
	require.NoError(t, err)

	def, err = cluster.SignCreator(secret, def)
	require.NoError(t, err)

	def, err = def.SetDefinitionHashes()
	require.NoError(t, err)

	err = def.VerifyHashes()
	require.NoError(t, err)

	err = def.VerifySignatures()
	require.NoError(t, err)

	return def
}
