// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

	record, err := EncodeENR(r)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(record))
	}))

	resp, err := queryBootnodeENR(context.Background(), srv.URL, 0)
	require.NoError(t, err)
	require.Equal(t, record, resp)
}

func TestQueryBootnodeENR_DNS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*10)
	defer cancel()

	_, err := queryBootnodeENR(ctx, "http://this.does.not.exist:123", 0)
	require.Error(t, err)
	require.True(t, errors.Is(err, context.DeadlineExceeded))
}

func TestQueryBootnodeENR_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*10)
	defer cancel()

	_, err := queryBootnodeENR(ctx, "http://127.0.0.1:1", 0)
	require.Error(t, err)
	require.True(t, errors.Is(err, context.DeadlineExceeded))
}

func TestQueryBootnodeENR_Invalid(t *testing.T) {
	_, err := queryBootnodeENR(context.Background(), "this is not a url", 0)
	require.Error(t, err)
}
