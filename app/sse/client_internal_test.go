// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package sse

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
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
		require.Equal(t, "/eth/v1/events", r.URL.Path)

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Connection", "keep-alive")
		wg.Done()
		time.Sleep(100 * time.Millisecond)
	}))
	defer ts.Close()

	// Create SSE client and add to waitgroup.
	cl, err := newClient(ts.URL, make(http.Header))
	require.NoError(t, err)
	eventHandler := func(ctx context.Context, event *event, url string) error { return nil }

	wg.Add(1)
	errCh := make(chan error)
	go func() { errCh <- cl.start(ctx, eventHandler) }()

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
	client := &client{}

	_, err := client.parseEvent(r)
	require.NoError(t, err)
	require.Equal(t, 10*time.Millisecond, client.retry)
}

func TestParseEventInvalidRetry(t *testing.T) {
	r := bufio.NewReader(bytes.NewBufferString("retry: ???\n\n"))
	client := &client{}

	_, err := client.parseEvent(r)
	require.NoError(t, err)
	require.Equal(t, time.Duration(0), client.retry)
}

func TestParseEvent(t *testing.T) {
	tests := []struct {
		name  string
		data  string
		event *event
		err   error
	}{
		{
			name: "parse no data",
			data: "\n\n",
			event: &event{
				ID:    "",
				Event: "",
				Data:  nil,
			},
			err: nil,
		},
		{
			name: "parse id",
			data: "id: 123\n\n",
			event: &event{
				ID:    "123",
				Event: "",
				Data:  nil,
			},
			err: nil,
		},
		{
			name: "parse event",
			data: "event: create\n\n",
			event: &event{
				ID:    "",
				Event: "create",
				Data:  nil,
			},
			err: nil,
		},
		{
			name: "parse data",
			data: "data: some data\n\n",
			event: &event{
				ID:    "",
				Event: "",
				Data:  []byte("some data"),
			},
			err: nil,
		},
		{
			name: "parse multiline data",
			data: "data: some data\ndata: multiline data\n\n",
			event: &event{
				ID:    "",
				Event: "",
				Data:  []byte("some data\nmultiline data"),
			},
			err: nil,
		},
		{
			name: "parse multiline data complex",
			data: "data: some data\r\ndata: multiline data\r\n\r\n",
			event: &event{
				ID:    "",
				Event: "",
				Data:  []byte("some data\nmultiline data"),
			},
			err: nil,
		},
		{
			name: "parse empty type",
			data: ": some comment\n\n",
			event: &event{
				ID:    "",
				Event: "",
				Data:  nil,
			},
			err: nil,
		},
		{
			name: "parse unsupported field",
			data: "unsupported field\n\n",
			event: &event{
				ID:    "",
				Event: "",
				Data:  nil,
			},
			err: nil,
		},
		{
			name: "parse multiple types",
			data: "id:123\nevent:create\ndata:this is some data\n\n",
			event: &event{
				ID:    "123",
				Event: "create",
				Data:  []byte("this is some data"),
			},
			err: nil,
		},
		{
			name: "parse multiple types space",
			data: "id: 123\nevent: create\ndata: this is some data\n\n",
			event: &event{
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
			event: &event{
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
			client := &client{}

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

func sseHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/single-event", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = fmt.Fprint(w, "data: singe event stream\n\n")
	})

	mux.HandleFunc("/500", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "oops 500", http.StatusInternalServerError)
	})

	mux.HandleFunc("/409", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "oops 409", http.StatusConflict)
	})

	return mux
}

func TestClientReconnect(t *testing.T) {
	server := httptest.NewServer(sseHandler())
	defer server.Close()

	// Single event stream will disconnect after emitting single event, sse
	// client should automatically reconnect until context deadline stops it.
	client, err := newClientForT(server.URL, "single-event")
	require.NoError(t, err)
	client.retry = 0

	counter := 0
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	handler := func(context.Context, *event, string) error {
		counter++
		if counter == 5 {
			cancel()
		}

		return nil
	}

	_ = client.start(ctx, handler)

	require.Equal(t, 5, counter)
}

func TestClientError409(t *testing.T) {
	server := httptest.NewServer(sseHandler())
	defer server.Close()

	eventHandler := func(context.Context, *event, string) error { return nil }

	// /409 endpoint will return 409 status code which should trigger an error.
	client, err := newClientForT(server.URL, "409")
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()

	err = client.start(ctx, eventHandler)
	require.Error(t, err)
	require.ErrorContains(t, err, "bad response status code")
}

func TestClientEventHandlerErrorPropagation(t *testing.T) {
	server := httptest.NewServer(sseHandler())
	defer server.Close()

	parserErr := errors.New("fail always")

	eventHandler := func(context.Context, *event, string) error { return parserErr }

	// /single-event endpoint will emit single event but our handler will
	// fail to parse it. We check if error returned by parser is passed back
	// to the error handler and if error returned by error handler is passed
	// back on stream end.
	client, err := newClientForT(server.URL, "single-event")
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()

	err = client.start(ctx, eventHandler)
	require.ErrorIs(t, err, parserErr, "expected error from event handler to be returned")
}
