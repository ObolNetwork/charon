// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestRunBootnode(t *testing.T) {
	temp := t.TempDir()

	config := Config{
		DataDir:   temp,
		LogConfig: log.DefaultConfig(),
		P2PConfig: p2p.Config{TCPAddrs: []string{testutil.AvailableAddr(t).String()}},
		HTTPAddr:  testutil.AvailableAddr(t).String(),
	}

	_, err := p2p.NewSavedPrivKey(temp)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = Run(ctx, config)
	testutil.SkipIfBindErr(t, err)
	require.NoError(t, err)
}

func TestRunBootnodeAutoP2P(t *testing.T) {
	temp := t.TempDir()

	config := Config{
		DataDir:   temp,
		LogConfig: log.DefaultConfig(),
		P2PConfig: p2p.Config{TCPAddrs: []string{testutil.AvailableAddr(t).String()}},
		HTTPAddr:  testutil.AvailableAddr(t).String(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := Run(ctx, config)
	testutil.SkipIfBindErr(t, err)
	require.Error(t, err)

	config.AutoP2PKey = true
	err = Run(ctx, config)
	testutil.SkipIfBindErr(t, err)
	require.NoError(t, err)
}

func TestServeAddrs(t *testing.T) {
	t.Run("multiaddrs", func(t *testing.T) {
		testServeAddrs(t,
			p2p.Config{TCPAddrs: []string{testutil.AvailableAddr(t).String()}},
			"",
			func(t *testing.T, data []byte) bool {
				t.Helper()
				var addrs []string
				err := json.Unmarshal(data, &addrs)
				if err != nil {
					t.Logf("failed to unmarshal multiaddrs: %v [%s]", err, data)
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
			},
		)
	})

	t.Run("enr", func(t *testing.T) {
		testServeAddrs(t,
			p2p.Config{TCPAddrs: []string{testutil.AvailableAddr(t).String()}},
			"enr",
			func(t *testing.T, data []byte) bool {
				t.Helper()
				r, err := enr.Parse(string(data))
				if err != nil {
					t.Logf("failed to parse enr: %v [%s]", err, data)
					return false
				}

				ip, ok := r.IP()
				require.True(t, ok)
				require.Equal(t, "127.0.0.1", ip.String())

				return true
			},
		)
	})

	t.Run("enr_ext_ip", func(t *testing.T) {
		testServeAddrs(t,
			p2p.Config{
				TCPAddrs:   []string{testutil.AvailableAddr(t).String()},
				ExternalIP: "222.222.222.222",
			},
			"enr",
			func(t *testing.T, data []byte) bool {
				t.Helper()
				r, err := enr.Parse(string(data))
				if err != nil {
					t.Logf("failed to parse enr: %v [%s]", err, data)
					return false
				}

				ip, ok := r.IP()
				require.True(t, ok)
				require.Equal(t, "222.222.222.222", ip.String())

				return true
			},
		)
	})

	t.Run("enr_ext_host", func(t *testing.T) {
		testServeAddrs(t,
			p2p.Config{
				TCPAddrs:     []string{testutil.AvailableAddr(t).String()},
				ExternalHost: "www.google.com",
			},
			"enr",
			func(t *testing.T, data []byte) bool {
				t.Helper()
				r, err := enr.Parse(string(data))
				if err != nil {
					t.Logf("failed to parse enr: %v [%s]", err, data)
					return false
				}

				ip, ok := r.IP()
				require.True(t, ok)
				if ip.IsLoopback() {
					t.Logf("ip is loopback")
					return false
				}

				return true
			},
		)
	})
}

func testServeAddrs(t *testing.T, p2pConfig p2p.Config, path string, asserter func(*testing.T, []byte) bool) {
	t.Helper()
	temp := t.TempDir()

	config := Config{
		AutoP2PKey: true,
		DataDir:    temp,
		LogConfig:  log.DefaultConfig(),
		P2PConfig:  p2pConfig,
		HTTPAddr:   testutil.AvailableAddr(t).String(),
	}

	ctx, cancel := context.WithCancel(context.Background())

	var eg errgroup.Group
	eg.Go(func() error {
		err := Run(ctx, config)
		cancel()
		testutil.SkipIfBindErr(t, err)

		return err
	})
	eg.Go(func() error {
		ok := assert.Eventually(t, func() bool {
			if ctx.Err() != nil {
				return true
			}
			resp, err := http.Get(fmt.Sprintf("http://%s/%s", config.HTTPAddr, path))
			if err != nil {
				t.Logf("failed to get: %v", err)
				return false
			}
			defer resp.Body.Close()
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Logf("failed to decode: %v", err)
				return false
			}

			return asserter(t, b)
		}, 2*time.Second, 100*time.Millisecond)
		cancel()

		if !ok {
			return errors.New("assert failed")
		}

		return nil
	})

	require.NoError(t, eg.Wait())
}
