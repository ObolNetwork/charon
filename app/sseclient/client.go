// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package sseclient

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

type Event struct {
	ID        string
	Event     string
	Data      []byte
	Timestamp time.Time
}

type (
	ErrorHandler func(err error, url string) error
	EventHandler func(ctx context.Context, e *Event, url string, options map[string]string) error
)

type Client struct {
	URL        string
	Retry      time.Duration
	HTTPClient *http.Client
	Headers    http.Header
}

var errStreamConn = errors.New("cannot connect to the stream")

func New(url string) *Client {
	return &Client{
		URL:        url,
		HTTPClient: &http.Client{},
		Headers:    make(http.Header),
	}
}

// Start connects to the SSE stream. This function will block until SSE stream is stopped.
func (c *Client) Start(ctx context.Context, eventFn EventHandler, errorFn ErrorHandler, opts map[string]string) error {
	timeout := c.Retry / 32
	timer := time.NewTimer(0)

	stop := func() {
		timer.Stop()

		select {
		case <-timer.C:
		default:
		}
	}
	defer stop()

	for {
		// Function blocks here.
		err := c.connect(ctx, eventFn, opts)

		switch {
		case err == nil, errors.Is(err, io.EOF):
			// Reset timeout if no error.
			timeout = c.Retry / 32
		case errors.Is(err, ctx.Err()):
			// Exit function if context errored.
			return nil
		default:
			// If error is not stream-related error, do not attempt retries and return the error.
			if !errors.Is(err, errStreamConn) {
				return errorFn(err, c.URL)
			}

			// Wait for the specified timeout (c.Retry/32 initially).
			stop()
			timer.Reset(timeout)

			select {
			case <-timer.C:
			case <-ctx.Done():
				return nil
			}

			// Increase the timeout by twice for the next potential failure, up to c.Retry.
			if timeout < c.Retry {
				timeout *= 2
			}
		}
	}
}

func (c *Client) connect(ctx context.Context, eventFn EventHandler, opts map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return errors.Wrap(err, "create new request")
	}

	for h, vs := range c.Headers {
		for _, v := range vs {
			req.Header.Add(h, v)
		}
	}
	req.Header.Set("Accept", "text/event-stream")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return errStreamConn
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		r := bufio.NewReader(resp.Body)

		for {
			event, err := c.parseEvent(r)
			if err != nil {
				return err
			}

			if len(event.Data) == 0 {
				continue
			}

			if err := eventFn(ctx, event, c.URL, opts); err != nil {
				return err
			}
		}
	default:
		return errors.New("bad response status code", z.Int("status_code", resp.StatusCode))
	}
}

func (c *Client) parseEvent(r *bufio.Reader) (*Event, error) {
	event := &Event{
		Event:     "message",
		Timestamp: time.Now(),
	}

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

			c.Retry = time.Duration(ms) * time.Millisecond
		case "id":
			event.ID = string(parts[1])
		case "event":
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
		if err == io.EOF && len(line) != 0 {
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
