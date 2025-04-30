// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package sseclient_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/sseclient"
)

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
	t.Parallel()

	server := httptest.NewServer(sseHandler())
	defer server.Close()

	// Single event stream will disconnect after emitting single event, sse
	// client should automatically reconnect until context deadline stops it.
	client := sseclient.New(server.URL + "/single-event")
	client.Retry = 0

	counter := 0
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	handler := func(context.Context, *sseclient.Event, string, map[string]string) error {
		counter++
		if counter == 5 {
			cancel()
		}

		return nil
	}
	errorHandler := func(error, string) error { return nil }

	_ = client.Start(ctx, handler, errorHandler, nil)

	require.Equal(t, 5, counter)
}

func TestClientError409(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(sseHandler())
	defer server.Close()

	ok := false
	eventHandler := func(context.Context, *sseclient.Event, string, map[string]string) error { return nil }
	errorHandler := func(error, string) error {
		ok = true

		return errors.New("stop")
	}

	// /409 endpoint will return 409 status code which should trigger an error.
	client := sseclient.New(server.URL + "/409")

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()

	_ = client.Start(ctx, eventHandler, errorHandler, nil)

	require.True(t, ok)
}

func TestClientEventHandlerErrorPropagation(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(sseHandler())
	defer server.Close()

	parserErr := errors.New("fail always")
	streamErr := errors.New("stop the stream")

	var receivedByHandler error

	eventHandler := func(context.Context, *sseclient.Event, string, map[string]string) error { return parserErr }
	errorHandler := func(err error, url string) error {
		receivedByHandler = err

		return streamErr
	}

	// /single-event endpoint will emit single event but our handler will
	// fail to parse it. We check if error returned by parser is passed back
	// to the error handler and if error returned by error handler is passed
	// back on stream end.
	client := sseclient.New(server.URL + "/single-event")

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()

	err := client.Start(ctx, eventHandler, errorHandler, nil)
	if !errors.Is(err, streamErr) {
		t.Fatalf("stream client dropped error handler error")
	}

	if !errors.Is(receivedByHandler, parserErr) {
		t.Fatalf("stream client did not pass parser error to error handler")
	}
}
