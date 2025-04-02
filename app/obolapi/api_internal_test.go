// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWithTimeout(t *testing.T) {
	// no timeout = 10s timeout
	oapi, err := New("http://url.com")
	require.NoError(t, err)
	require.Equal(t, defaultTimeout, oapi.reqTimeout)

	// with timeout = timeout specified
	timeout := 1 * time.Minute
	oapi, err = New("http://url.com", WithTimeout(timeout))
	require.NoError(t, err)
	require.Equal(t, timeout, oapi.reqTimeout)
}

func TestHttpPost(t *testing.T) {
	tests := []struct {
		name          string
		body          []byte
		headers       map[string]string
		server        *httptest.Server
		endpoint      string
		expectedError string
	}{
		{
			name:     "default scenario",
			body:     nil,
			headers:  nil,
			endpoint: "/post-request",
			server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, r.URL.Path, "/post-request")
				require.Equal(t, r.Method, http.MethodPost)
				require.Equal(t, r.Header.Get("Content-Type"), "application/json")
				w.WriteHeader(http.StatusOK)
			})),
			expectedError: "",
		},
		{
			name:     "default scenario with body and headers",
			body:     []byte(`{"test_body_key": "test_body_value"}`),
			headers:  map[string]string{"test_header_key": "test_header_value"},
			endpoint: "/post-request",
			server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, r.URL.Path, "/post-request")
				require.Equal(t, r.Method, http.MethodPost)
				require.Equal(t, r.Header.Get("Content-Type"), "application/json")
				require.Equal(t, r.Header.Get("test_header_key"), "test_header_value") //nolint:canonicalheader

				data, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				defer r.Body.Close()
				require.JSONEq(t, string(data), `{"test_body_key": "test_body_value"}`)

				w.WriteHeader(http.StatusOK)
				_, err = w.Write([]byte(`"OK"`))
				require.NoError(t, err)
			})),
			expectedError: "",
		},
		{
			name:     "status code not 2XX",
			body:     nil,
			headers:  nil,
			endpoint: "/post-request",
			server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, r.URL.Path, "/post-request")
				require.Equal(t, r.Method, http.MethodPost)
				require.Equal(t, r.Header.Get("Content-Type"), "application/json")

				w.WriteHeader(http.StatusBadRequest)
				_, err := w.Write([]byte(`"Bad Request response"`))
				require.NoError(t, err)
			})),
			expectedError: "POST failed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testServerURL, err := url.ParseRequestURI(test.server.URL)
			require.NoError(t, err)
			err = httpPost(context.Background(), testServerURL.JoinPath(test.endpoint), test.body, test.headers)
			if test.expectedError != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, test.expectedError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestHttpGet(t *testing.T) {
	tests := []struct {
		name          string
		headers       map[string]string
		server        *httptest.Server
		endpoint      string
		expectedResp  []byte
		expectedError string
	}{
		{
			name:     "default scenario",
			headers:  nil,
			endpoint: "/get-request",
			server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, r.URL.Path, "/get-request")
				require.Equal(t, r.Method, http.MethodGet)
				require.Equal(t, r.Header.Get("Content-Type"), "application/json")
				w.WriteHeader(http.StatusOK)
			})),
			expectedError: "",
		},
		{
			name:     "default scenario with headers",
			headers:  map[string]string{"test_header_key": "test_header_value"},
			endpoint: "/get-request",
			server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, r.URL.Path, "/get-request")
				require.Equal(t, r.Method, http.MethodGet)
				require.Equal(t, r.Header.Get("Content-Type"), "application/json")
				require.Equal(t, r.Header.Get("test_header_key"), "test_header_value") //nolint:canonicalheader

				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(`"OK"`))
				require.NoError(t, err)
			})),
			expectedResp:  []byte(`"OK"`),
			expectedError: "",
		},
		{
			name:     "status code not 2XX",
			headers:  nil,
			endpoint: "/get-request",
			server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, r.URL.Path, "/get-request")
				require.Equal(t, r.Method, http.MethodGet)
				require.Equal(t, r.Header.Get("Content-Type"), "application/json")

				w.WriteHeader(http.StatusBadRequest)
				_, err := w.Write([]byte(`"Bad Request response"`))
				require.NoError(t, err)
			})),
			expectedResp:  []byte(`"Bad Request response"`),
			expectedError: "GET failed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testServerURL, err := url.ParseRequestURI(test.server.URL)
			require.NoError(t, err)
			respBody, err := httpGet(context.Background(), testServerURL.JoinPath(test.endpoint), test.headers)
			if test.expectedError != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, test.expectedError)
			} else {
				require.NoError(t, err)
				defer respBody.Close()
				resp, err := io.ReadAll(respBody)
				require.NoError(t, err)
				require.Equal(t, string(resp), string(test.expectedResp))
			}
		})
	}
}
