// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package cluster

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

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
	secret, err := crypto.GenerateKey()
	require.NoError(t, err)

	addr := crypto.PubkeyToAddress(secret.PublicKey)
	digest := testutil.RandomRoot()
	sig, err := crypto.Sign(digest[:], secret)
	require.NoError(t, err)

	t.Run("valid signature", func(t *testing.T) {
		ok, err := verifySig(addr.String(), digest[:], sig)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("invalid signature length", func(t *testing.T) {
		var invalidSig [70]byte
		ok, err := verifySig(addr.String(), digest[:], invalidSig[:])
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid signature length")
		require.False(t, ok)
	})

	t.Run("invalid recovery id", func(t *testing.T) {
		var newSig [65]byte
		copy(newSig[:], sig)
		newSig[k1RecIdx] = byte(165) // Make the last byte invalid.

		ok, err := verifySig(addr.String(), digest[:], newSig[:])
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid recovery id")
		require.False(t, ok)
	})

	t.Run("sig ending with 27/28", func(t *testing.T) {
		var newSig [65]byte
		copy(newSig[:], sig)
		newSig[k1RecIdx] += 27 // Make last byte 27/28.

		ok, err := verifySig(addr.String(), digest[:], newSig[:])
		require.NoError(t, err)
		require.True(t, ok)
	})
}

func TestFetchDefinition(t *testing.T) {
	lock, _, _ := NewForT(t, 1, 2, 3, 0)
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
