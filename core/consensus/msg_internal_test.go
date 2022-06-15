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

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

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
		"39933362de95b6dabf0b6512bc19a43826debf8cb71936d99e251b053ad8846d",
		hex.EncodeToString(hash[:]),
	)
}

func TestSigning(t *testing.T) {
	privkey, err := crypto.GenerateKey()
	require.NoError(t, err)

	v, err := core.UnsignedDataSetToProto(testutil.RandomUnsignedDataSet(t))
	require.NoError(t, err)
	pv, err := core.UnsignedDataSetToProto(testutil.RandomUnsignedDataSet(t))
	require.NoError(t, err)

	msg := &pbv1.QBFTMsg{
		Type:          rand.Int63(),
		Duty:          core.DutyToProto(core.Duty{Type: core.DutyType(rand.Int()), Slot: rand.Int63()}),
		PeerIdx:       rand.Int63(),
		Round:         rand.Int63(),
		Value:         v,
		PreparedRound: rand.Int63(),
		PreparedValue: pv,
		Signature:     nil,
	}

	signed, err := signMsg(msg, privkey)
	require.NoError(t, err)

	ok, err := verifyMsgSig(signed, &privkey.PublicKey)
	require.NoError(t, err)
	require.True(t, ok)

	privkey2, err := crypto.GenerateKey()
	require.NoError(t, err)
	ok, err = verifyMsgSig(signed, &privkey2.PublicKey)
	require.NoError(t, err)
	require.False(t, ok)
}
