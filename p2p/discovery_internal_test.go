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

package p2p

import (
	"context"
	"crypto/ecdsa"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
)

func TestQueryBootnodeENR(t *testing.T) {
	p2pKey, err := ecdsa.GenerateKey(crypto.S256(), rand.New(rand.NewSource(0)))
	require.NoError(t, err)

	var r enr.Record
	err = enode.SignV4(&r, p2pKey)
	require.NoError(t, err)

	db, err := enode.OpenDB("")
	require.NoError(t, err)

	enrStr := enode.NewLocalNode(db, p2pKey).Node().String()

	const header = "foo/bar"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, header, r.Header.Get("Charon-Cluster"))
		_, _ = w.Write([]byte(enrStr))
	}))

	resp, err := queryBootnodeENR(context.Background(), srv.URL, 0, header)
	require.NoError(t, err)
	require.Equal(t, enrStr, resp.String())
}

func TestQueryBootnodeENR_DNS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*10)
	defer cancel()

	_, err := queryBootnodeENR(ctx, "http://this.does.not.exist:123", 0, "")
	require.Error(t, err)
	require.True(t, errors.Is(err, context.DeadlineExceeded))
}

func TestQueryBootnodeENR_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*10)
	defer cancel()

	_, err := queryBootnodeENR(ctx, "http://127.0.0.1:1", 0, "")
	require.Error(t, err)
	require.True(t, errors.Is(err, context.DeadlineExceeded))
}

func TestQueryBootnodeENR_Invalid(t *testing.T) {
	_, err := queryBootnodeENR(context.Background(), "this is not a url", 0, "")
	require.Error(t, err)
}
