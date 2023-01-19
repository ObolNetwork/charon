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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util/keymanager"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil"
)

func TestImportKeystores(t *testing.T) {
	var (
		ctx        = context.Background()
		numSecrets = 4
		secrets    []*bls_sig.SecretKey
	)

	for i := 0; i < numSecrets; i++ {
		_, secret, err := tbls.Keygen()
		require.NoError(t, err)
		secrets = append(secrets, secret)
	}

	var (
		keystores []keystore.Keystore
		passwords []string
	)
	for _, secret := range secrets {
		password, err := testutil.RandomHex32()
		require.NoError(t, err)

		store, err := keystore.Encrypt(secret, password, rand.Reader)
		require.NoError(t, err)

		keystores = append(keystores, store)
		passwords = append(passwords, password)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Run("successful import keystores", func(t *testing.T) {
		cl := keymanager.New(srv.URL)
		err := cl.ImportKeystores(ctx, keystores, passwords)
		require.NoError(t, err)
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
