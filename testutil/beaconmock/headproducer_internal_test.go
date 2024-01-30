// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package beaconmock

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/r3labs/sse/v2"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/testutil"
)

func TestHeadProducer(t *testing.T) {
	bmock, err := New()
	require.NoError(t, err)

	defer bmock.Close()

	base := testutil.MustParseURL(t, bmock.Address())

	unsupportedTopicErr := errors.New("unknown topic requested")

	tests := []struct {
		name       string
		topics     []string
		statusCode int
		expectErr  bool
	}{
		{
			name:       "2 supported topics requested",
			topics:     []string{"head", "block"},
			statusCode: http.StatusOK,
		},
		{
			name:       "head topic",
			topics:     []string{"head"},
			statusCode: http.StatusOK,
		},
		{
			name:       "block topic",
			topics:     []string{"block"},
			statusCode: http.StatusOK,
		},
		{
			name:       "unsupported topic",
			topics:     []string{"exit"},
			statusCode: http.StatusInternalServerError,
			expectErr:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rawURL := fmt.Sprintf("eth/v1/events?topics=%s", strings.Join(test.topics, "&topics="))
			endpoint := testutil.MustParseURL(t, rawURL)
			addr := base.ResolveReference(endpoint).String()

			requiredTopics := make(map[string]bool)
			for _, topic := range test.topics {
				requiredTopics[topic] = true
			}

			client := sse.NewClient(addr,
				func(c *sse.Client) {
					c.ResponseValidator = func(c *sse.Client, resp *http.Response) error {
						require.Equal(t, test.statusCode, resp.StatusCode)

						if resp.StatusCode == http.StatusInternalServerError {
							data, err := io.ReadAll(resp.Body)
							require.NoError(t, err)
							require.Contains(t, string(data), "unknown topic")

							return unsupportedTopicErr
						}

						return nil
					}
				},
				func(c *sse.Client) {
					c.ReconnectStrategy = StopBackOff{}
				},
			)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Mock head updates.
			go func() {
				var i int
				for ctx.Err() == nil {
					bmock.headProducer.updateHead(eth2p0.Slot(i))
					i++
					time.Sleep(time.Millisecond)
				}
			}()

			if test.expectErr {
				require.ErrorIs(t, client.SubscribeWithContext(ctx, addr, func(msg *sse.Event) {}), unsupportedTopicErr)
			} else {
				actualTopics := make(map[string]bool)
				require.NoError(t, client.SubscribeWithContext(ctx, addr, func(msg *sse.Event) {
					require.True(t, requiredTopics[string(msg.Event)])

					actualTopics[string(msg.Event)] = true
					if len(requiredTopics) == len(actualTopics) {
						cancel()
					}
				}))
			}
		})
	}
}

// Refer https://github.com/cenkalti/backoff/blob/v4/backoff.go#L46 for the following snippet.
// We don't need the full dependency since we don't want these tests to support exponential backoff.
// We want simple, fast tests where a single event is sent by the server and is intercepted by the client, or
// it produces an error.

// Stop indicates that no more retries should be made for use in NextBackOff().
const Stop time.Duration = -1

// StopBackOff is a fixed backoff policy that always returns backoff.Stop for
// NextBackOff(), meaning that the operation should never be retried.
type StopBackOff struct{}

func (b StopBackOff) Reset() {}

func (b StopBackOff) NextBackOff() time.Duration { return Stop }
