// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package relay

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cmd/relay"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

// StartRelay starts a charon relay and returns its http multiaddr endpoint.
func StartRelay(parentCtx context.Context, t *testing.T) string {
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
			LogConfig:     log.DefaultConfig(),
			AutoP2PKey:    true,
			MaxResPerPeer: 8,
			MaxConns:      1024,
		})
		if err != nil {
			log.Warn(parentCtx, "Relay stopped with error", err)
		} else {
			log.Info(parentCtx, "Relay stopped without error")
		}

		errChan <- err
	}()

	endpoint := "http://" + addr

	// Wait up to 10s for bootnode to become available.
	ctx, cancel := context.WithTimeout(parentCtx, 10*time.Second)
	defer cancel()

	isUp := make(chan struct{})

	go func() {
		for ctx.Err() == nil {
			// #nosec G107
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
			if err != nil {
				return
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				time.Sleep(time.Millisecond * 100)
				continue
			}
			defer resp.Body.Close()

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
