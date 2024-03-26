// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/testutil"
)

func TestLeftPad(t *testing.T) {
	b := []byte{0x01, 0x02}
	require.Equal(t, []byte{0x01, 0x02}, leftPad(b, 1))
	require.Equal(t, []byte{0x01, 0x02}, leftPad(b, 2))
	require.Equal(t, []byte{0x00, 0x01, 0x02}, leftPad(b, 3))
	require.Equal(t, []byte{0x00, 0x00, 0x01, 0x02}, leftPad(b, 4))
}

func TestVerifySig(t *testing.T) {
	secret, err := k1.GeneratePrivateKey()
	require.NoError(t, err)

	addr := eth2util.PublicKeyToAddress(secret.PubKey())
	digest := testutil.RandomRoot()
	sig, err := k1util.Sign(secret, digest[:])
	require.NoError(t, err)

	t.Run("valid signature", func(t *testing.T) {
		ok, err := verifySig(addr, digest[:], sig)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("invalid signature length", func(t *testing.T) {
		var invalidSig [70]byte
		ok, err := verifySig(addr, digest[:], invalidSig[:])
		require.Error(t, err)
		require.ErrorContains(t, err, "signature not 65 bytes")
		require.False(t, ok)
	})

	t.Run("invalid recovery id", func(t *testing.T) {
		var newSig [65]byte
		copy(newSig[:], sig)
		newSig[64] = byte(165) // Make the last byte invalid.

		ok, err := verifySig(addr, digest[:], newSig[:])
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid recovery id")
		require.False(t, ok)
	})

	t.Run("sig ending with 27/28", func(t *testing.T) {
		var newSig [65]byte
		copy(newSig[:], sig)
		newSig[64] += 27 // Make last byte 27/28.

		ok, err := verifySig(addr, digest[:], newSig[:])
		require.NoError(t, err)
		require.True(t, ok)
	})
}

func TestFetchDefinition(t *testing.T) {
	seed := 0
	random := rand.New(rand.NewSource(int64(seed)))
	lock, _, _ := NewForT(t, 1, 2, 3, seed, random)
	validDef := lock.Definition
	invalidDef := Definition{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimSpace(r.URL.Path) {
		case "/validDef":
			b, _ := validDef.MarshalJSON()
			_, _ = w.Write(b)
		case "/invalidDef":
			b, _ := invalidDef.MarshalJSON()
			_, _ = w.Write(b)
		case "/nonok":
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	tests := []struct {
		name    string
		url     string
		want    Definition
		wantErr bool
	}{
		{
			name:    "Fetch valid definition",
			url:     fmt.Sprintf("%s/%s", server.URL, "validDef"),
			want:    validDef,
			wantErr: false,
		},
		{
			name:    "Fetch invalid definition",
			url:     fmt.Sprintf("%s/%s", server.URL, "invalidDef"),
			want:    invalidDef,
			wantErr: true,
		},
		{
			name:    "HTTP status is not in the 200 range",
			url:     fmt.Sprintf("%s/%s", server.URL, "nonok"),
			want:    invalidDef,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FetchDefinition(context.Background(), tt.url)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestCreateValidatorKeysDir(t *testing.T) {
	tmp := t.TempDir()

	// First attempt must succeed.
	dir, err := CreateValidatorKeysDir(tmp)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(dir, tmp))
	require.True(t, strings.HasSuffix(dir, "validator_keys"))

	// Second attempt shall succeed as long as the dir is empty.
	dir, err = CreateValidatorKeysDir(tmp)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(dir, tmp))
	require.True(t, strings.HasSuffix(dir, "validator_keys"))

	// Create a file in the directory to make it non-empty.
	err = os.WriteFile(path.Join(dir, "file"), []byte("data"), 0o644)
	require.NoError(t, err)
	_, err = CreateValidatorKeysDir(tmp)
	require.ErrorContains(t, err, "directory not empty")

	t.Run("mkdir error", func(t *testing.T) {
		// Parent directory does not exist
		_, err := CreateValidatorKeysDir(path.Join(tmp, "nonexistent"))
		require.ErrorContains(t, err, "mkdir")
	})
}
