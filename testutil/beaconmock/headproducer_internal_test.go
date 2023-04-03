// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package beaconmock

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/r3labs/sse/v2"
	"github.com/stretchr/testify/require"
	"gopkg.in/cenkalti/backoff.v1"

	"github.com/obolnetwork/charon/app/errors"
)

func TestHeadProducer(t *testing.T) {
	bmock, err := New()
	require.NoError(t, err)

	defer bmock.Close()

	base, err := url.Parse(bmock.Address())
	require.NoError(t, err)

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
			endpoint, err := url.Parse(fmt.Sprintf("eth/v1/events?topics=%s", strings.Join(test.topics, "&topics=")))
			require.NoError(t, err)

			addr := base.ResolveReference(endpoint).String()

			requiredTopics := make(map[string]bool)
			for _, topic := range test.topics {
				requiredTopics[topic] = true
			}

			client := sse.NewClient(addr, func(c *sse.Client) {
				c.ResponseValidator = func(c *sse.Client, resp *http.Response) error {
					require.Equal(t, test.statusCode, resp.StatusCode)

					if resp.StatusCode == http.StatusInternalServerError {
						data, err := io.ReadAll(resp.Body)
						require.NoError(t, err)
						require.Contains(t, string(data), "unknown topic")

						return backoff.Permanent(unsupportedTopicErr)
					}

					return nil
				}
			})

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
