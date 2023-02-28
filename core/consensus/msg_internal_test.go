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

package consensus

import (
	"encoding/hex"
	"math/rand"
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -update -clean

func TestHashProto(t *testing.T) {
	rand.Seed(0)
	set := testutil.RandomUnsignedDataSet(t)
	testutil.RequireGoldenJSON(t, set)

	setPB, err := core.UnsignedDataSetToProto(set)
	require.NoError(t, err)
	hash, err := hashProto(setPB)
	require.NoError(t, err)

	require.Equal(t,
		"09d28bb0414151be4330871ca94a473a69938c8c3ee934b18c85b9e9c7118858",
		hex.EncodeToString(hash[:]),
	)
}

//go:generate go test . -update

func TestSigning(t *testing.T) {
	privkey, err := k1.GeneratePrivateKey()
	require.NoError(t, err)

	msg := randomMsg(t)

	signed, err := signMsg(msg, privkey)
	require.NoError(t, err)

	ok, err := verifyMsgSig(signed, privkey.PubKey())
	require.NoError(t, err)
	require.True(t, ok)

	privkey2, err := k1.GeneratePrivateKey()
	require.NoError(t, err)
	ok, err = verifyMsgSig(signed, privkey2.PubKey())
	require.NoError(t, err)
	require.False(t, ok)
}

// randomMsg returns a random qbft message.
func randomMsg(t *testing.T) *pbv1.QBFTMsg {
	t.Helper()

	v, err := core.UnsignedDataSetToProto(testutil.RandomUnsignedDataSet(t))
	require.NoError(t, err)
	pv, err := core.UnsignedDataSetToProto(testutil.RandomUnsignedDataSet(t))
	require.NoError(t, err)

	anyV, err := anypb.New(v)
	require.NoError(t, err)
	anyPV, err := anypb.New(pv)
	require.NoError(t, err)

	return &pbv1.QBFTMsg{
		Type:          rand.Int63(),
		Duty:          core.DutyToProto(core.Duty{Type: core.DutyType(rand.Int()), Slot: rand.Int63()}),
		PeerIdx:       rand.Int63(),
		Round:         rand.Int63(),
		Value:         anyV,
		PreparedRound: rand.Int63(),
		PreparedValue: anyPV,
		Signature:     nil,
	}
}
