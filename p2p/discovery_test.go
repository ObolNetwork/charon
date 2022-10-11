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

package p2p_test

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/rand"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestExternalHost(t *testing.T) {
	p2pKey, err := ecdsa.GenerateKey(crypto.S256(), rand.New(rand.NewSource(0)))
	require.NoError(t, err)

	addr1 := testutil.AvailableAddr(t)
	addr2 := testutil.AvailableAddr(t)

	config := p2p.Config{
		UDPAddr:      fmt.Sprintf("0.0.0.0:%d", addr1.Port),
		ExternalHost: "localhost",
		TCPAddrs:     []string{fmt.Sprintf("0.0.0.0:%d", addr2.Port)},
	}

	localNode, db, err := p2p.NewLocalEnode(config, p2pKey)
	require.NoError(t, err)
	defer db.Close()

	udpNode, err := p2p.NewUDPNode(context.Background(), config, localNode, p2pKey, nil)
	testutil.SkipIfBindErr(t, err)
	require.NoError(t, err)

	defer udpNode.Close()
}
