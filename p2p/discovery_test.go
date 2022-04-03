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
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestExternalHost(t *testing.T) {
	ctx := context.Background()
	p2pKey, err := ecdsa.GenerateKey(crypto.S256(), rand.New(rand.NewSource(0)))
	require.NoError(t, err)

	addr1 := testutil.AvailableAddr(t)
	addr2 := testutil.AvailableAddr(t)

	config := p2p.Config{
		UDPAddr:      fmt.Sprintf("0.0.0.0:%d", addr1.Port),
		ExteranlHost: "localhost",
		TCPAddrs:     []string{fmt.Sprintf("0.0.0.0:%d", addr2.Port)},
	}

	localNode, db, err := p2p.NewLocalEnode(config, p2pKey)
	require.NoError(t, err)
	defer db.Close()

	udpNode, err := p2p.NewUDPNode(ctx, config, localNode, p2pKey, nil)
	if err != nil && strings.Contains(err.Error(), "bind: address already in use") {
		// This sometimes happens, not sure how to lock available ports...
		t.Skip("couldn't bind to available port")
		return
	}
	require.NoError(t, err)
	defer udpNode.Close()
}
