// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/app/z"
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
		expectedIs    error
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
		{
			name:     "status code 404 Not Found",
			body:     nil,
			headers:  nil,
			endpoint: "/post-request",
			server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				_, err := w.Write([]byte(`{"message":"cluster lock is not found"}`))
				require.NoError(t, err)
			})),
			expectedError: "POST failed",
			expectedIs:    ErrLockNotFound,
		},
		{
			name:     "status code 409 Conflict (duplicate ignored)",
			body:     nil,
			headers:  nil,
			endpoint: "/post-request",
			server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, r.URL.Path, "/post-request")
				require.Equal(t, r.Method, http.MethodPost)
				require.Equal(t, r.Header.Get("Content-Type"), "application/json")

				w.WriteHeader(http.StatusConflict)
				_, err := w.Write([]byte(`"Duplicate request"`))
				require.NoError(t, err)
			})),
			expectedError: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testServerURL, err := url.ParseRequestURI(test.server.URL)
			require.NoError(t, err)

			cl, err := New(test.server.URL)
			require.NoError(t, err)

			err = cl.httpPost(context.Background(), testServerURL.JoinPath(test.endpoint), test.body, test.headers)
			if test.expectedError != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, test.expectedError)

				if test.expectedIs != nil {
					require.ErrorIs(t, err, test.expectedIs)
					require.True(t, z.ContainsField(err, z.Int("status", http.StatusNotFound)))
				} else {
					require.NotErrorIs(t, err, ErrLockNotFound)
				}
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

			cl, err := New(test.server.URL)
			require.NoError(t, err)

			respBody, err := cl.httpGet(context.Background(), testServerURL.JoinPath(test.endpoint), test.headers)
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

func TestUserAgent(t *testing.T) {
	charonUA := "charon/" + version.Version.String()

	tests := []struct {
		name    string
		options []func(*Client)
		want    string
	}{
		{
			name: "default",
			want: charonUA,
		},
		{
			name:    "with product",
			options: []func(*Client){WithUserAgent("lido-dv-exit/v0.7.0")},
			want:    "lido-dv-exit/v0.7.0 " + charonUA,
		},
		{
			name:    "empty product",
			options: []func(*Client){WithUserAgent("")},
			want:    charonUA,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var got []string

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = append(got, r.Header.Get("User-Agent"))

				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			cl, err := New(srv.URL, test.options...)
			require.NoError(t, err)

			u, err := url.ParseRequestURI(srv.URL)
			require.NoError(t, err)

			ctx := context.Background()

			require.NoError(t, cl.httpPost(ctx, u, nil, nil))

			body, err := cl.httpGet(ctx, u, nil)
			require.NoError(t, err)
			require.NoError(t, body.Close())

			require.NoError(t, cl.httpDelete(ctx, u, nil))

			require.Equal(t, []string{test.want, test.want, test.want}, got)
		})
	}
}

func TestPostPartialExitsLockNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"statusCode":404,"message":"cluster lock is not found"}`))
	}))
	defer srv.Close()

	cl, err := New(srv.URL)
	require.NoError(t, err)

	key, err := k1.GeneratePrivateKey()
	require.NoError(t, err)

	err = cl.PostPartialExits(context.Background(), make([]byte, 32), 1, key)
	require.ErrorIs(t, err, ErrLockNotFound)
	require.NotErrorIs(t, err, ErrNoValue)
}
