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
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestRunBootnode(t *testing.T) {
	temp, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	config := bootnodeConfig{
		DataDir:   temp,
		LogConfig: log.DefaultConfig(),
		P2PConfig: p2p.Config{UDPAddr: testutil.AvailableAddr(t).String()},
		HTTPAddr:  testutil.AvailableAddr(t).String(),
	}

	err = runGenP2PKey(io.Discard, config.P2PConfig, temp)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = runBootnode(ctx, config)
	if err != nil && strings.Contains(err.Error(), "bind: permission denied") {
		t.Skip("Skipping due to sporadic bind: address already in use")
		return
	}
	require.NoError(t, err)
}
