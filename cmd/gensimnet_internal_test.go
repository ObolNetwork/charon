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

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -run=TestGenSimnet -update

func TestGenSimnet(t *testing.T) {
	dir, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	var buf bytes.Buffer
	conf := simnetConfig{
		ClusterDir: dir,
		NumNodes:   4,
		Threshold:  3,
		PortStart:  8000,
		TestBinary: "charon",
	}

	err = runGenSimnet(&buf, conf)
	require.NoError(t, err)

	out := buf.Bytes()
	out = bytes.Replace(out, []byte(dir), []byte("charon-simnet"), 1)
	testutil.RequireGoldenBytes(t, out)

	// TODO(corver): Assert generated files.
}
