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
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
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

	def, err := newDefFromConfig(ctx, conf)
	require.NoError(t, err)

	err = validateDef(ctx, false, def)
	require.Error(t, err, "zero address")

	goerli, err := hex.DecodeString(strings.TrimPrefix(eth2util.Goerli.ForkVersionHex, "0x"))
	require.NoError(t, err)
	def.ForkVersion = goerli
	err = validateDef(ctx, false, def)
	require.NoError(t, err)

	err = validateDef(ctx, true, def) // Validate with insecure keys set to true
	require.NoError(t, err)

	mainnet, err := hex.DecodeString(strings.TrimPrefix(eth2util.Mainnet.ForkVersionHex, "0x"))
	require.NoError(t, err)
	def.ForkVersion = mainnet
	err = validateDef(ctx, conf.InsecureKeys, def)
	require.Error(t, err, "zero address")
}
