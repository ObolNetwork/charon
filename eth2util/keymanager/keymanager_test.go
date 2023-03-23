// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

const testAuthToken = "Bearer api-token-test"

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

		cl := keymanager.New(srv.URL, testAuthToken)
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

		cl := keymanager.New(srv.URL, testAuthToken)
		err := cl.ImportKeystores(ctx, keystores, passwords)
		require.ErrorContains(t, err, "failed posting keys")
	})

	t.Run("mismatching lengths", func(t *testing.T) {
		cl := keymanager.New("", testAuthToken)
		err := cl.ImportKeystores(ctx, keystores, []string{})
		require.ErrorContains(t, err, "lengths of keystores and passwords don't match")
	})
}

func TestVerifyConnection(t *testing.T) {
	ctx := context.Background()

	t.Run("successful ping", func(t *testing.T) {
		srv := httptest.NewServer(nil)
		defer srv.Close()

		cl := keymanager.New(srv.URL, testAuthToken)
		require.NoError(t, cl.VerifyConnection(ctx))
	})

	t.Run("cannot ping address", func(t *testing.T) {
		cl := keymanager.New("1.1.1.1", testAuthToken)
		require.Error(t, cl.VerifyConnection(ctx))
		require.ErrorContains(t, cl.VerifyConnection(ctx), "cannot ping address")
	})

	t.Run("invalid address", func(t *testing.T) {
		cl := keymanager.New("1.1.0:34", testAuthToken)
		require.Error(t, cl.VerifyConnection(ctx))
		require.ErrorContains(t, cl.VerifyConnection(ctx), "parse address")
	})
}

// mockKeymanagerReq is a mock keymanager request for use in tests.
type mockKeymanagerReq struct {
	Keystores []noopKeystore `json:"keystores"`
	Passwords []string       `json:"passwords"`
}

type mockKeymanagerReqJSON struct {
	Keystores []string `json:"keystores"`
	Passwords []string `json:"passwords"`
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
