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
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -run=TestCreateCluster -update -clean

func TestCreateCluster(t *testing.T) {
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
			},
		}, {
			Name: "splitkeys",
			Config: clusterConfig{
				NumNodes:  4,
				Threshold: 3,
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
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			if test.Prep != nil {
				test.Config = test.Prep(t, test.Config)
			}

			test.Config.WithdrawalAddr = defaultWithdrawalAddr
			test.Config.Network = defaultNetwork

			testCreateCluster(t, test.Config)
		})
	}
}

func testCreateCluster(t *testing.T, conf clusterConfig) {
	t.Helper()

	dir, err := os.MkdirTemp("", "")
	require.NoError(t, err)
	conf.ClusterDir = dir

	var buf bytes.Buffer
	err = runCreateCluster(&buf, conf)
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
	conf := clusterConfig{
		NumNodes:       4,
		Threshold:      3,
		WithdrawalAddr: "0x0000000000000000000000000000000000000000",
		Network:        "gnosis",
	}
	err := validateClusterConfig(conf)
	require.Error(t, err, "zero address")

	conf.Network = "prater"
	err = validateClusterConfig(conf)
	require.NoError(t, err)
}

func TestInvalidThreshold(t *testing.T) {
	conf := clusterConfig{
		NumNodes:  5,
		Threshold: 3,
	}
	err := validateClusterConfig(conf)
	require.EqualError(t, err, "threshold less than minimum (min required >= 4)")
}
