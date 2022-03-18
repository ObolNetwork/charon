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

package p2p_test

import (
	"crypto/ecdsa"
	"math/rand"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/p2p"
)

func TestNewPeer(t *testing.T) {
	p2pKey, err := ecdsa.GenerateKey(crypto.S256(), rand.New(rand.NewSource(0)))
	require.NoError(t, err)

	var r enr.Record
	r.SetSeq(0)

	err = enode.SignV4(&r, p2pKey)
	require.NoError(t, err)

	p, err := p2p.NewPeer(r, 0)
	require.NoError(t, err)

	require.Equal(t, "16Uiu2HAm87ieJpGmqjdqVF6Y4LAodxdsUY2sVCX5b31QVHCLt116", p.ID.Pretty())
}
