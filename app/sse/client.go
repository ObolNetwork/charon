// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package sse

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/expbackoff"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

type event struct {
	ID        string
	Event     string
	Data      []byte
	Timestamp time.Time
}

type (
	EventHandler func(ctx context.Context, e *event, addr string) error
)

type client struct {
	addr       string
	sseURL     *url.URL
	retry      time.Duration
	httpClient *http.Client
	headers    http.Header
}

var (
	errStreamConn = errors.New("cannot connect to the stream")
	defaultRetry  = time.Second
)

func newClient(addr string, header http.Header) (*client, error) {
	prefixedAddr := addr
	if !strings.HasPrefix(addr, "http") {
		prefixedAddr = "http://" + addr
	}

	u, err := url.Parse(prefixedAddr)
	if err != nil {
		return nil, errors.Wrap(err, "parse bn addr", z.Str("addr", addr))
	}

	u.Path = "/eth/v1/events"
	q := u.Query()
	q.Add("topics", sseHeadEvent)
	q.Add("topics", sseChainReorgEvent)
	q.Add("topics", sseBlockGossipEvent)
	q.Add("topics", sseBlockEvent)
	u.RawQuery = q.Encode()

	return &client{
		addr:       addr,
		sseURL:     u,
		retry:      defaultRetry,
		httpClient: &http.Client{},
		headers:    header,
	}, nil
}

func newClientForT(addr, path string) (*client, error) {
	prefixedAddr := addr
	if !strings.HasPrefix(addr, "http") {
		prefixedAddr = "http://" + addr
	}

	u, err := url.Parse(prefixedAddr)
	if err != nil {
		return nil, errors.Wrap(err, "parse bn addr", z.Str("addr", addr))
	}

	u.Path = path

	// For testing purposes, we use a different retry duration.
	return &client{
		addr:       addr,
		sseURL:     u,
		retry:      100 * time.Millisecond,
		httpClient: &http.Client{},
		headers:    make(http.Header),
	}, nil
}

// start connects to the SSE stream. This function will block until SSE stream is stopped.
func (c *client) start(ctx context.Context, eventFn EventHandler) error {
	backoff := func() {}
	backoffSet := false

	for {
		err := c.connect(ctx, eventFn)

		switch {
		case err == nil, errors.Is(err, io.EOF):
			// Reset the retry.
			c.retry = defaultRetry
			backoffSet = false

			continue
		case ctx.Err() != nil:
			// Exit function if context done.
			return nil //nolint:nilerr
		default:
			// If error is not stream-related error, do not attempt retries and return the error.
			if !errors.Is(err, errStreamConn) {
				return errors.Wrap(err, "handle SSE payload", z.Str("url", c.sseURL.String()))
			}

			if !backoffSet {
				backoffConfig := expbackoff.Config{
					BaseDelay:  c.retry,
					Multiplier: 1.6,
					Jitter:     0.2,
					MaxDelay:   c.retry * 2,
				}
				backoff = expbackoff.New(ctx, expbackoff.WithConfig(backoffConfig))
				backoffSet = true
			}

			backoff()
		}
	}
}

func (c *client) connect(ctx context.Context, eventFn EventHandler) error {
	log.Debug(ctx, "Connecting to SSE stream", z.Str("url", c.sseURL.String()))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.sseURL.String(), nil)
	if err != nil {
		return errors.Wrap(err, "create new request")
	}

	req.Header = c.headers.Clone()
	req.Header.Set("Accept", "text/event-stream")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return errStreamConn
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		r := bufio.NewReader(resp.Body)

		for {
			select {
			case <-ctx.Done():
				return nil
			default:
				event, err := c.parseEvent(r)
				if err != nil {
					return err
				}

				if len(event.Data) == 0 {
					continue
				}

				if err := eventFn(ctx, event, c.addr); err != nil {
					return err
				}
			}
		}
	default:
		return errors.New("bad response status code", z.Int("status_code", resp.StatusCode))
	}
}

func (c *client) parseEvent(r *bufio.Reader) (*event, error) {
	event := &event{}

	for {
		parts, err := formatAndValidateEvent(r)
		if err != nil {
			return nil, err
		}

		if len(parts) == 0 {
			return event, nil
		}

		// Check response type.
		switch string(parts[0]) {
		case "retry":
			ms, err := strconv.Atoi(string(parts[1]))
			if err != nil {
				continue
			}

			c.retry = time.Duration(ms) * time.Millisecond
		case "id":
			event.ID = string(parts[1])
		case "event":
			event.Timestamp = time.Now()
			event.Event = string(parts[1])
		case "data":
			if event.Data != nil {
				event.Data = append(event.Data, '\n')
			}

			event.Data = append(event.Data, parts[1]...)
		default:
			continue
		}
	}
}

func formatAndValidateEvent(r *bufio.Reader) ([][]byte, error) {
	line, err := r.ReadBytes('\n')
	if err != nil {
		// Connection was lost during reading.
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, errStreamConn
		}

		if errors.Is(err, io.EOF) && len(line) != 0 {
			return nil, errors.New("incomplete event at the end of the stream")
		}

		return nil, errors.Wrap(err, "read event")
	}

	// Remove \n suffix.
	if len(line) != 0 && line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}

	// Remove \r suffix.
	if len(line) != 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}

	if len(line) == 0 {
		return [][]byte{}, nil
	}

	parts := bytes.SplitN(line, []byte(":"), 2)

	// Make sure parts[1] always exist.
	if len(parts) == 1 {
		parts = append(parts, nil)
	}

	// Remove prefix after ":".
	if len(parts[1]) > 0 && parts[1][0] == ' ' {
		parts[1] = parts[1][1:]
	}

	return parts, nil
}
