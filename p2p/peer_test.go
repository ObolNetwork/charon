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
	"math/rand"
	"os"
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/p2p"
	tblsv2 "github.com/obolnetwork/charon/tbls/v2"
	herumiImpl "github.com/obolnetwork/charon/tbls/v2/herumi"
	"github.com/obolnetwork/charon/testutil"
)

func TestMain(m *testing.M) {
	tblsv2.SetImplementation(herumiImpl.Herumi{})
	os.Exit(m.Run())
}

func TestNewPeer(t *testing.T) {
	p2pKey := testutil.GenerateInsecureK1Key(t, rand.New(rand.NewSource(0)))

	record, err := enr.New(p2pKey)
	require.NoError(t, err)

	p, err := p2p.NewPeerFromENR(record, 0)
	require.NoError(t, err)

	require.Equal(t, "16Uiu2HAm87ieJpGmqjdqVF6Y4LAodxdsUY2sVCX5b31QVHCLt116", p.ID.String())
}

func TestNewHost(t *testing.T) {
	privKey, err := k1.GeneratePrivateKey()
	require.NoError(t, err)

	_, err = p2p.NewTCPNode(context.Background(), p2p.Config{}, privKey, p2p.NewOpenGater())
	require.NoError(t, err)
}

func TestVerifyP2PKey(t *testing.T) {
	lock, keys, _ := cluster.NewForT(t, 1, 3, 4, 0)

	peers, err := lock.Peers()
	require.NoError(t, err)

	for _, key := range keys {
		require.NoError(t, p2p.VerifyP2PKey(peers, key))
	}

	key, err := k1.GeneratePrivateKey()
	require.NoError(t, err)
	require.Error(t, p2p.VerifyP2PKey(peers, key))
}

func TestPeerIDKey(t *testing.T) {
	lock, keys, _ := cluster.NewForT(t, 1, 3, 4, 0)

	peers, err := lock.Peers()
	require.NoError(t, err)

	for i, p := range peers {
		pk, err := p2p.PeerIDToKey(p.ID)
		require.NoError(t, err)
		require.True(t, keys[i].PubKey().IsEqual(pk))

		pID, err := p2p.PeerIDFromKey(pk)
		require.NoError(t, err)
		require.Equal(t, p.ID, pID)
	}
}
