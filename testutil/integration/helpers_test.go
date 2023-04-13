// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package integration_test

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cmd/relay"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

var integration = flag.Bool("integration", false, "Enable this package's integration tests")

func skipIfDisabled(t *testing.T) {
	t.Helper()
	if !*integration {
		t.Skip("Integration tests are disabled")
	}
}

// startRelay starts a charon relay and returns its http multiaddr endpoint.
func startRelay(parentCtx context.Context, t *testing.T) string {
	t.Helper()

	dir := t.TempDir()

	addr := testutil.AvailableAddr(t).String()

	errChan := make(chan error, 1)
	go func() {
		err := relay.Run(parentCtx, relay.Config{
			DataDir:  dir,
			HTTPAddr: addr,
			P2PConfig: p2p.Config{
				TCPAddrs: []string{testutil.AvailableAddr(t).String()},
			},
			LogConfig: log.Config{
				Level:  "error",
				Format: "console",
			},
			AutoP2PKey:    true,
			MaxResPerPeer: 8,
			MaxConns:      1024,
		})
		t.Logf("Relay stopped: err=%v", err)
		errChan <- err
	}()

	endpoint := "http://" + addr

	// Wait up to 5s for bootnode to become available.
	ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
	defer cancel()

	isUp := make(chan struct{})
	go func() {
		for ctx.Err() == nil {
			_, err := http.Get(endpoint)
			if err != nil {
				time.Sleep(time.Millisecond * 100)
				continue
			}
			close(isUp)

			return
		}
	}()

	for {
		select {
		case <-ctx.Done():
			require.Fail(t, "Relay context canceled before startup")
			return ""
		case err := <-errChan:
			testutil.SkipIfBindErr(t, err)
			require.Fail(t, "Relay exitted before startup", "err=%v", err)

			return ""
		case <-isUp:
			return endpoint
		}
	}
}

// asserter provides an abstract callback asserter.
type asserter struct {
	Timeout   time.Duration
	callbacks sync.Map // map[string]bool
}

// Await waits for all nodes to ping each other or time out.
func (a *asserter) await(ctx context.Context, t *testing.T, expect int) error {
	t.Helper()

	var actual map[interface{}]bool

	ok := assert.Eventually(t, func() bool {
		if ctx.Err() != nil {
			return true
		}
		actual = make(map[interface{}]bool)
		a.callbacks.Range(func(k, v interface{}) bool {
			actual[k] = true

			return true
		})

		return len(actual) >= expect
	}, a.Timeout, time.Millisecond*10)

	if ctx.Err() != nil {
		return context.Canceled
	}

	if !ok {
		return errors.New(fmt.Sprintf("Timeout waiting for callbacks, expect=%d, actual=%d: %v", expect, len(actual), actual))
	}

	return nil
}

// externalIP returns the hosts external IP.
// Copied from https://stackoverflow.com/questions/23558425/how-do-i-get-the-local-ip-address-in-go.
func externalIP(t *testing.T) string {
	t.Helper()

	ifaces, err := net.Interfaces()
	require.NoError(t, err)

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		require.NoError(t, err)
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}

			return ip.String()
		}
	}

	t.Fatal("no network?")

	return ""
}

func peerCtx(ctx context.Context, idx int) context.Context {
	return log.WithCtx(ctx, z.Int("peer_index", idx))
}
