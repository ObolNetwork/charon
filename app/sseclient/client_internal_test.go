// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package sseclient

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
)

func TestReconnect(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var wg sync.WaitGroup
	// Start test server.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/eth/events", r.URL.Path)

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Connection", "keep-alive")
		wg.Done()
		time.Sleep(100 * time.Millisecond)
	}))
	defer ts.Close()

	// Create SSE client and add to waitgroup.
	cl := New(ts.URL + "/v1/eth/events")
	eventHandler := func(ctx context.Context, event *Event, url string, opts map[string]string) error { return nil }
	errHandler := func(err error, url string) error { return nil }

	wg.Add(1)
	errCh := make(chan error)
	go func() { errCh <- cl.Start(ctx, eventHandler, errHandler, nil) }()

	// Wait for waitgroup to be finished by the test server (= call from SSE client received).
	wg.Wait()
	// Close connection from test server to the client.
	ts.CloseClientConnections()
	// Add to waitgroup.
	wg.Add(1)
	// Wait for the SSE client to reconnect to the server, send new request and SSE server to unblock.
	wg.Wait()

	cancel()
	require.NoError(t, <-errCh)
}

func TestParseEventRetry(t *testing.T) {
	r := bufio.NewReader(bytes.NewBufferString("retry: 10\n\n"))
	client := &Client{}

	_, err := client.parseEvent(r)
	require.NoError(t, err)
	require.Equal(t, 10*time.Millisecond, client.Retry)
}

func TestParseEventInvalidRetry(t *testing.T) {
	r := bufio.NewReader(bytes.NewBufferString("retry: ???\n\n"))
	client := &Client{}

	_, err := client.parseEvent(r)
	require.NoError(t, err)
	require.Equal(t, time.Duration(0), client.Retry)
}

func TestParseEvent(t *testing.T) {
	tests := []struct {
		name  string
		data  string
		event *Event
		err   error
	}{
		{
			name: "parse no data",
			data: "\n\n",
			event: &Event{
				ID:    "",
				Event: "",
				Data:  nil,
			},
			err: nil,
		},
		{
			name: "parse id",
			data: "id: 123\n\n",
			event: &Event{
				ID:    "123",
				Event: "",
				Data:  nil,
			},
			err: nil,
		},
		{
			name: "parse event",
			data: "event: create\n\n",
			event: &Event{
				ID:    "",
				Event: "create",
				Data:  nil,
			},
			err: nil,
		},
		{
			name: "parse data",
			data: "data: some data\n\n",
			event: &Event{
				ID:    "",
				Event: "",
				Data:  []byte("some data"),
			},
			err: nil,
		},
		{
			name: "parse multiline data",
			data: "data: some data\ndata: multiline data\n\n",
			event: &Event{
				ID:    "",
				Event: "",
				Data:  []byte("some data\nmultiline data"),
			},
			err: nil,
		},
		{
			name: "parse multiline data complex",
			data: "data: some data\r\ndata: multiline data\r\n\r\n",
			event: &Event{
				ID:    "",
				Event: "",
				Data:  []byte("some data\nmultiline data"),
			},
			err: nil,
		},
		{
			name: "parse empty type",
			data: ": some comment\n\n",
			event: &Event{
				ID:    "",
				Event: "",
				Data:  nil,
			},
			err: nil,
		},
		{
			name: "parse unsupported field",
			data: "unsupported field\n\n",
			event: &Event{
				ID:    "",
				Event: "",
				Data:  nil,
			},
			err: nil,
		},
		{
			name: "parse multiple types",
			data: "id:123\nevent:create\ndata:this is some data\n\n",
			event: &Event{
				ID:    "123",
				Event: "create",
				Data:  []byte("this is some data"),
			},
			err: nil,
		},
		{
			name: "parse multiple types space",
			data: "id: 123\nevent: create\ndata: this is some data\n\n",
			event: &Event{
				ID:    "123",
				Event: "create",
				Data:  []byte("this is some data"),
			},
			err: nil,
		},
		{
			name: "parse multiple types new line",
			data: `id: 123
event: create
data: this is some data
unsupported field
: some comment
data: multiline data

`,
			event: &Event{
				ID:    "123",
				Event: "create",
				Data:  []byte("this is some data\nmultiline data"),
			},
			err: nil,
		},
		{
			name:  "incomplete event",
			data:  "data: test", // missing \n to be complete event
			event: nil,
			err:   errors.New("incomplete event at the end of the stream"),
		},
		{
			name:  "empty data EOF",
			data:  "",
			event: nil,
			err:   io.EOF,
		},
		{
			name:  "EOF",
			data:  "data: test\n",
			event: nil,
			err:   io.EOF,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := bufio.NewReader(bytes.NewBufferString(test.data))
			client := &Client{}

			event, err := client.parseEvent(r)
			if test.event != nil {
				require.Equal(t, test.event.Event, event.Event)
				require.Equal(t, test.event.Data, event.Data)
				require.Equal(t, test.event.ID, event.ID)
			}
			if test.err != nil {
				require.ErrorContains(t, err, test.err.Error())
			}
		})
	}
}
