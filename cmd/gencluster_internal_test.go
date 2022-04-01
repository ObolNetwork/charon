// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/keystore"
)

//go:generate go test . -run=TestGenCluster -update -clean

func TestGenCluster(t *testing.T) {
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
				PortStart: 8000,
				Simnet:    true,
			},
		}, {
			Name: "splitkeys",
			Config: clusterConfig{
				NumNodes:  4,
				Threshold: 3,
				PortStart: 8000,
				SplitKeys: true,
			},
			Prep: func(t *testing.T, config clusterConfig) clusterConfig {
				keyDir, err := os.MkdirTemp("", "")
				require.NoError(t, err)

				_, secret1, err := tbls.Keygen()
				require.NoError(t, err)
				_, secret2, err := tbls.Keygen()
				require.NoError(t, err)

				err = keystore.StoreKeys([]*bls_sig.SecretKey{secret1, secret2}, keyDir)
				require.NoError(t, err)

				config.KeysDir = keyDir

				return config
			},
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			if test.Prep != nil {
				test.Config = test.Prep(t, test.Config)
			}
			testGenCluster(t, test.Config)
		})
	}
}

func testGenCluster(t *testing.T, conf clusterConfig) {
	t.Helper()

	conf.TestBinary = "charon"

	dir, err := os.MkdirTemp("", "")
	require.NoError(t, err)
	conf.ClusterDir = dir

	var buf bytes.Buffer
	err = runGenCluster(&buf, conf)
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

	t.Run("runsh", func(t *testing.T) {
		b, err := os.ReadFile(path.Join(dir, "node0", "run.sh"))
		require.NoError(t, err)

		b = bytes.ReplaceAll(b, []byte(dir), []byte("charon"))
		testutil.RequireGoldenBytes(t, b)
	})
}
