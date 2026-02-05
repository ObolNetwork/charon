// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster

import (
	"context"
	"encoding/json"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "HTTPS URL",
			input: "https://example.com/cluster-lock.json",
			want:  true,
		},
		{
			name:  "HTTP URL",
			input: "http://example.com/cluster-lock.json",
			want:  true,
		},
		{
			name:  "HTTPS URL with port",
			input: "https://example.com:8080/path/to/lock.json",
			want:  true,
		},
		{
			name:  "Local file path",
			input: "/path/to/cluster-lock.json",
			want:  false,
		},
		{
			name:  "Relative file path",
			input: "./cluster-lock.json",
			want:  false,
		},
		{
			name:  "Windows-style path",
			input: "C:\\path\\to\\cluster-lock.json",
			want:  false,
		},
		{
			name:  "Empty string",
			input: "",
			want:  false,
		},
		{
			name:  "FTP URL (not supported)",
			input: "ftp://example.com/file.json",
			want:  false,
		},
		{
			name:  "File URL scheme (not supported)",
			input: "file:///path/to/file.json",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsURL(tt.input)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestFetchClusterLockBytes(t *testing.T) {
	seed := 0
	random := rand.New(rand.NewSource(int64(seed)))
	lock, _, _ := NewForT(t, 1, 2, 3, seed, random)

	validLockBytes, err := json.Marshal(lock)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimSpace(r.URL.Path) {
		case "/valid":
			_, _ = w.Write(validLockBytes)
		case "/notfound":
			w.WriteHeader(http.StatusNotFound)
		case "/error":
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	tests := []struct {
		name    string
		url     string
		wantErr string
	}{
		{
			name:    "Fetch valid lock",
			url:     server.URL + "/valid",
			wantErr: "",
		},
		{
			name:    "HTTP 404 error",
			url:     server.URL + "/notfound",
			wantErr: "http error",
		},
		{
			name:    "HTTP 500 error",
			url:     server.URL + "/error",
			wantErr: "http error",
		},
		{
			name:    "Invalid URL",
			url:     "http://invalid.invalid.invalid/lock.json",
			wantErr: "fetch cluster-lock.json from URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fetchClusterLockBytes(context.Background(), tt.url)
			if tt.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErr)

				return
			}

			require.NoError(t, err)
			require.Equal(t, validLockBytes, got)
		})
	}
}

func TestLoadClusterLockBytes(t *testing.T) {
	seed := 0
	random := rand.New(rand.NewSource(int64(seed)))
	lock, _, _ := NewForT(t, 1, 2, 3, seed, random)

	validLockBytes, err := json.Marshal(lock)
	require.NoError(t, err)

	// Create a temporary file with valid lock content
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "cluster-lock.json")
	err = os.WriteFile(tmpFile, validLockBytes, 0o644)
	require.NoError(t, err)

	// Create HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(validLockBytes)
	}))
	defer server.Close()

	tests := []struct {
		name      string
		pathOrURL string
		wantErr   string
	}{
		{
			name:      "Load from local file",
			pathOrURL: tmpFile,
			wantErr:   "",
		},
		{
			name:      "Load from HTTP URL",
			pathOrURL: server.URL + "/lock.json",
			wantErr:   "",
		},
		{
			name:      "Non-existent local file",
			pathOrURL: filepath.Join(tmpDir, "nonexistent.json"),
			wantErr:   "read cluster-lock.json from disk",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := loadClusterLockBytes(context.Background(), tt.pathOrURL)
			if tt.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErr)

				return
			}

			require.NoError(t, err)
			require.Equal(t, validLockBytes, got)
		})
	}
}
