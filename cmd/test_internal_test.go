// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestBeaconBasicAuth verifies that HTTP basic authentication is correctly extracted
// from URLs and applied to requests.
func TestBeaconBasicAuth(t *testing.T) {
	const (
		expectedUser = "testuser"
		expectedPass = "testpass123"
	)

	// Create a test server that validates basic auth
	authValidated := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if Authorization header is present
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Validate basic auth credentials
		const prefix = "Basic "
		if len(auth) < len(prefix) || auth[:len(prefix)] != prefix {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		expected := expectedUser + ":" + expectedPass
		if string(decoded) == expected {
			authValidated = true
			// Return a valid response for /eth/v1/node/health
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer server.Close()

	// Test with auth in URL
	t.Run("with_basic_auth", func(t *testing.T) {
		authValidated = false
		// Create URL with embedded credentials
		urlWithAuth := "http://" + expectedUser + ":" + expectedPass + "@" + server.Listener.Addr().String()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		result := beaconPingTest(ctx, &testBeaconConfig{}, urlWithAuth)

		require.True(t, authValidated, "Basic auth credentials were not validated by server")
		require.Equal(t, testVerdictOk, result.Verdict, "Expected test to pass with valid credentials")
	})

	// Test without auth - server should reject
	t.Run("without_auth_fails", func(t *testing.T) {
		authValidated = false
		// Use URL without credentials
		urlWithoutAuth := "http://" + server.Listener.Addr().String()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		result := beaconPingTest(ctx, &testBeaconConfig{}, urlWithoutAuth)

		require.False(t, authValidated, "Auth should not have been validated")
		require.Equal(t, testVerdictFail, result.Verdict, "Expected test to fail without credentials")
	})
}

// TestParseEndpointURL verifies URL parsing and credential extraction.
func TestParseEndpointURL(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantCleanURL string
		wantHasAuth  bool
		wantUsername string
		wantPassword string
		wantError    bool
	}{
		{
			name:         "URL without auth",
			input:        "https://beacon.example.com/path",
			wantCleanURL: "https://beacon.example.com/path",
			wantHasAuth:  false,
		},
		{
			name:         "URL with auth",
			input:        "https://user:pass@beacon.example.com/path",
			wantCleanURL: "https://beacon.example.com/path",
			wantHasAuth:  true,
			wantUsername: "user",
			wantPassword: "pass",
		},
		{
			name:         "URL with special chars in password",
			input:        "https://user:p@ss!123@beacon.example.com",
			wantCleanURL: "https://beacon.example.com",
			wantHasAuth:  true,
			wantUsername: "user",
			wantPassword: "p@ss!123",
		},
		{
			name:         "URL with query params",
			input:        "https://user:pass@beacon.example.com/path?query=value",
			wantCleanURL: "https://beacon.example.com/path?query=value",
			wantHasAuth:  true,
			wantUsername: "user",
			wantPassword: "pass",
		},
		{
			name:         "HTTP URL with auth",
			input:        "http://admin:secret@localhost:5051",
			wantCleanURL: "http://localhost:5051",
			wantHasAuth:  true,
			wantUsername: "admin",
			wantPassword: "secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanURL, parsedURL, err := parseEndpointURL(tt.input)

			if tt.wantError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.wantCleanURL, cleanURL)

			if tt.wantHasAuth {
				require.NotNil(t, parsedURL.User)
				require.Equal(t, tt.wantUsername, parsedURL.User.Username())
				password, hasPassword := parsedURL.User.Password()
				require.True(t, hasPassword)
				require.Equal(t, tt.wantPassword, password)
			} else {
				require.Nil(t, parsedURL.User)
			}
		})
	}
}
