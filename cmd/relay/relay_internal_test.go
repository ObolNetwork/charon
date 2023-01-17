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

package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestRunBootnode(t *testing.T) {
	temp, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	config := Config{
		DataDir:   temp,
		LogConfig: log.DefaultConfig(),
		P2PConfig: p2p.Config{UDPAddr: testutil.AvailableAddr(t).String()},
		HTTPAddr:  testutil.AvailableAddr(t).String(),
	}

	_, err = p2p.NewSavedPrivKey(temp)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = Run(ctx, config)
	testutil.SkipIfBindErr(t, err)
	require.NoError(t, err)
}

func TestRunBootnodeAutoP2P(t *testing.T) {
	temp, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	config := Config{
		DataDir:   temp,
		LogConfig: log.DefaultConfig(),
		P2PConfig: p2p.Config{UDPAddr: testutil.AvailableAddr(t).String()},
		HTTPAddr:  testutil.AvailableAddr(t).String(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = Run(ctx, config)
	testutil.SkipIfBindErr(t, err)
	require.Error(t, err)

	config.AutoP2PKey = true
	err = Run(ctx, config)
	testutil.SkipIfBindErr(t, err)
	require.NoError(t, err)
}

func TestServeMultiAddrs(t *testing.T) {
	temp, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	config := Config{
		AutoP2PKey: true,
		DataDir:    temp,
		LogConfig:  log.DefaultConfig(),
		P2PConfig:  p2p.Config{TCPAddrs: []string{testutil.AvailableAddr(t).String()}},
		HTTPAddr:   testutil.AvailableAddr(t).String(),
	}

	ctx, cancel := context.WithCancel(context.Background())

	var eg errgroup.Group
	eg.Go(func() error {
		return Run(ctx, config)
	})
	eg.Go(func() error {
		require.Eventually(t, func() bool {
			b, err := http.Get(fmt.Sprintf("http://%s", config.HTTPAddr))
			if err != nil {
				t.Logf("failed to get: %v", err)
				return false
			}
			var addrs []string
			err = json.NewDecoder(b.Body).Decode(&addrs)
			if err != nil {
				t.Logf("failed to decode: %v", err)
				return false
			}

			if len(addrs) == 0 {
				t.Logf("no addrs")
				return false
			}

			for _, addr := range addrs {
				_, err := ma.NewMultiaddr(addr)
				if err != nil {
					t.Logf("failed to parse multiaddr: %v [%v]", err, addr)
					return false
				}
			}

			return true
		}, 2*time.Second, 100*time.Millisecond)
		cancel()

		return Run(ctx, config)
	})

	err = eg.Wait()
	testutil.SkipIfBindErr(t, err)
	require.NoError(t, err)
}
