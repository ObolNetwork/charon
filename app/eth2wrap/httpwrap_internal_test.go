// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"net/http"
	"net/http/httptest"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
)

func CreateTestHTTPRequest(t *testing.T, method, path string, body []byte) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, "http://localhost:5050"+path, nil)
	require.NoError(t, err)
	return req
}

func TestProxyRequestInvalidAddress(t *testing.T) {
	// Create a httpAdapter with an invalid address
	httpAdapter := newHTTPAdapter(nil, "http://invalid", nil, 0)

	// Proxy request via the invalid address
	req := CreateTestHTTPRequest(t, "GET", "", nil)
	_, err := httpAdapter.ProxyRequest(t.Context(), req)
	require.Error(t, err)
}

func TestProxyRequestWithInlineBasicAuth(t *testing.T) {
	// Create a test HTTP server that requires basic auth
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "user" || password != "pass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Insert basic auth credentials into the URL
	targetURL := server.URL
	targetURLWithAuth := "http://user:pass@" + targetURL[len("http://"):]
	// Create a httpAdapter pointing to the test server
	httpAdapter := newHTTPAdapter(nil, targetURLWithAuth, nil, 0)

	// Proxy request via the httpAdapter
	req := CreateTestHTTPRequest(t, "GET", "", nil)
	resp, err := httpAdapter.ProxyRequest(t.Context(), req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestProxyRequestWithHeadersBasicAuth(t *testing.T) {
	// Create a test HTTP server that requires basic auth
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "headeruser" || password != "headerpass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create a httpAdapter pointing to the test server with headers for basic auth
	headers := map[string]string{
		"Authorization": "Basic aGVhZGVydXNlcjpoZWFkZXJwYXNz", // base64 of "headeruser:headerpass"
	}
	httpAdapter := newHTTPAdapter(nil, server.URL, headers, 0)

	// Proxy request via the httpAdapter
	req := CreateTestHTTPRequest(t, "GET", "", nil)
	resp, err := httpAdapter.ProxyRequest(t.Context(), req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestProxyRequestWithDifferentStatusCodes(t *testing.T) {
	// Create a test HTTP server that returns different status codes based on the path
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/success":
			w.WriteHeader(http.StatusOK)
		case "/notfound":
			w.WriteHeader(http.StatusNotFound)
		case "/error":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()

	// Create a httpAdapter pointing to the test server
	httpAdapter := newHTTPAdapter(nil, server.URL, nil, 0)

	testCases := []struct {
		path           string
		expectedStatus int
	}{
		{"/success", http.StatusOK},
		{"/notfound", http.StatusNotFound},
		{"/error", http.StatusInternalServerError},
		{"/badrequest", http.StatusBadRequest},
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			req := CreateTestHTTPRequest(t, "GET", tc.path, nil)
			resp, err := httpAdapter.ProxyRequest(t.Context(), req)
			require.NoError(t, err)
			require.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestProxyRequestWithClosedServer(t *testing.T) {
	// Create a test HTTP server that closes connection immediately to simulate a faulty server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.Close() // Close immediately to simulate fault

	// Create a httpAdapter pointing to the closed server
	httpAdapter := newHTTPAdapter(nil, server.URL, nil, 0)

	// Proxy request via the httpAdapter
	req := CreateTestHTTPRequest(t, "GET", "", nil)
	_, err := httpAdapter.ProxyRequest(t.Context(), req)
	require.Error(t, err)

	// Confirm the error is a connection refused error
	var sysErr *os.SyscallError
	require.True(t, errors.As(err, &sysErr))
	require.Equal(t, sysErr.Err, syscall.ECONNREFUSED)
}
