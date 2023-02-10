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

package keymanager_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"

	"github.com/obolnetwork/charon/eth2util/keymanager"
	"github.com/obolnetwork/charon/eth2util/keystore"
	tblsv2 "github.com/obolnetwork/charon/tbls/v2"
	tblsconv2 "github.com/obolnetwork/charon/tbls/v2/tblsconv"
)

func TestImportKeystores(t *testing.T) {
	var (
		ctx        = context.Background()
		numSecrets = 4
		secrets    []tblsv2.PrivateKey
	)

	for i := 0; i < numSecrets; i++ {
		secret, err := tblsv2.GenerateSecretKey()
		require.NoError(t, err)
		secrets = append(secrets, secret)
	}

	var (
		keystores []keystore.Keystore
		passwords []string
	)
	for _, secret := range secrets {
		password := randomHex32(t)

		store, err := keystore.Encrypt(secret, password, rand.Reader)
		require.NoError(t, err)

		keystores = append(keystores, store)
		passwords = append(passwords, password)
	}

	t.Run("2xx response", func(t *testing.T) {
		var receivedSecrets []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, r.URL.Path, "/eth/v1/keystores")

			data, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			defer func() {
				require.NoError(t, r.Body.Close())
			}()

			var req mockKeymanagerReq
			require.NoError(t, json.Unmarshal(data, &req))
			require.Equal(t, len(req.Keystores), len(req.Passwords))
			require.Equal(t, len(req.Keystores), numSecrets)

			for i := 0; i < numSecrets; i++ {
				secret, err := decrypt(t, req.Keystores[i], req.Passwords[i])
				require.NoError(t, err)

				receivedSecrets = append(receivedSecrets, hex.EncodeToString(secret[:]))
			}

			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		cl := keymanager.New(srv.URL)
		err := cl.ImportKeystores(ctx, keystores, passwords)
		require.NoError(t, err)

		// Convert original secrets to strings
		var originalSecrets []string
		for _, secret := range secrets {
			originalSecrets = append(originalSecrets, hex.EncodeToString(secret[:]))
		}

		require.Equal(t, originalSecrets, receivedSecrets)
	})

	t.Run("4xx response", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, r.URL.Path, "/eth/v1/keystores")
			w.WriteHeader(http.StatusForbidden)
		}))
		defer srv.Close()

		cl := keymanager.New(srv.URL)
		err := cl.ImportKeystores(ctx, keystores, passwords)
		require.ErrorContains(t, err, "failed posting keys")
	})

	t.Run("mismatching lengths", func(t *testing.T) {
		cl := keymanager.New("")
		err := cl.ImportKeystores(ctx, keystores, []string{})
		require.ErrorContains(t, err, "lengths of keystores and passwords don't match")
	})
}

func TestVerifyConnection(t *testing.T) {
	ctx := context.Background()

	t.Run("successful ping", func(t *testing.T) {
		srv := httptest.NewServer(nil)
		defer srv.Close()

		cl := keymanager.New(srv.URL)
		require.NoError(t, cl.VerifyConnection(ctx))
	})

	t.Run("cannot ping address", func(t *testing.T) {
		cl := keymanager.New("1.1.1.1")
		require.Error(t, cl.VerifyConnection(ctx))
		require.ErrorContains(t, cl.VerifyConnection(ctx), "cannot ping address")
	})

	t.Run("invalid address", func(t *testing.T) {
		cl := keymanager.New("1.1.0:34")
		require.Error(t, cl.VerifyConnection(ctx))
		require.ErrorContains(t, cl.VerifyConnection(ctx), "parse address")
	})
}

// mockKeymanagerReq is a mock keymanager request for use in tests.
type mockKeymanagerReq struct {
	Keystores []noopKeystore `json:"keystores"`
	Passwords []string       `json:"passwords"`
}

// noopKeystore is a mock keystore for use in tests.
type noopKeystore struct {
	Crypto map[string]interface{} `json:"crypto"`
}

// decrypt returns the secret from the encrypted keystore.
func decrypt(t *testing.T, store noopKeystore, password string) (tblsv2.PrivateKey, error) {
	t.Helper()

	decryptor := keystorev4.New()
	secretBytes, err := decryptor.Decrypt(store.Crypto, password)
	require.NoError(t, err)

	return tblsconv2.PrivkeyFromBytes(secretBytes)
}

// randomHex32 returns a random 32 character hex string.
func randomHex32(t *testing.T) string {
	t.Helper()

	b := make([]byte, 16)
	_, err := rand.Read(b)
	require.NoError(t, err)

	return hex.EncodeToString(b)
}
