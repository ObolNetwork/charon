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
	"os"
	"testing"

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/keystore"
)

//go:generate go test . -run=TestSplitKeyCluster -update

func TestSplitKeyCluster(t *testing.T) {
	keyDir, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	_, secret1, err := bls_sig.NewSigEth2().Keygen()
	require.NoError(t, err)
	_, secret2, err := bls_sig.NewSigEth2().Keygen()
	require.NoError(t, err)

	err = keystore.StoreKeys([]*bls_sig.SecretKey{secret1, secret2}, keyDir)
	require.NoError(t, err)

	clusterDir, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	var buf bytes.Buffer
	conf := splitKeyConfig{
		simnetConfig: simnetConfig{
			clusterDir: clusterDir,
			numNodes:   4,
			threshold:  3,
			portStart:  8000,
			testBinary: "charon",
		},
		KeyDir: keyDir,
	}

	err = runSplitKeyCluster(&buf, conf)
	require.NoError(t, err)

	out := buf.Bytes()
	out = bytes.Replace(out, []byte(clusterDir), []byte("charon-simnet"), 1)
	testutil.RequireGoldenBytes(t, out)

	// TODO(corver): Assert generated files.
}
