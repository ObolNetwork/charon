// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package integration_test

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cmd/relay"
	"github.com/obolnetwork/charon/p2p"
	tblsv2 "github.com/obolnetwork/charon/tbls/v2"
	"github.com/obolnetwork/charon/testutil"
)

var integration = flag.Bool("integration", false, "Enable this package's integration tests")

func skipIfDisabled(t *testing.T) {
	t.Helper()
	if !*integration {
		t.Skip("Integration tests are disabled")
	}
}

func TestMain(m *testing.M) {
	tblsv2.SetImplementation(tblsv2.Herumi{})
	os.Exit(m.Run())
}

// startRelay starts a charon relay and returns its http multiaddr endpoint.
func startRelay(ctx context.Context, t *testing.T) (string, <-chan error) {
	t.Helper()

	dir := t.TempDir()

	addr := testutil.AvailableAddr(t).String()

	errChan := make(chan error, 1)
	go func() {
		errChan <- relay.Run(ctx, relay.Config{
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
	}()

	endpoint := "http://" + addr

	// Wait for bootnode to become available.
	for ctx.Err() == nil {
		_, err := http.Get(endpoint)
		if err == nil {
			break
		}
		time.Sleep(time.Millisecond * 100)
	}

	return endpoint, errChan
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
