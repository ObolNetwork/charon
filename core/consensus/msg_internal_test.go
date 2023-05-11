// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus

import (
	"encoding/hex"
	"math/rand"
	"testing"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/core/qbft"
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
		"281aa1a75b2bd09f00f2d69bdf1256b83350dac475108cde608fc3f11428e54d",
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

func TestNewMsg(t *testing.T) {
	val1 := timestamppb.New(time.Time{})
	val2 := timestamppb.New(time.Now())
	hash1, err := hashProto(val1)
	require.NoError(t, err)
	hash2, err := hashProto(val2)
	require.NoError(t, err)

	any1, err := anypb.New(val1)
	require.NoError(t, err)
	any2, err := anypb.New(val2)
	require.NoError(t, err)

	values := map[[32]byte]*anypb.Any{
		hash1: any1,
		hash2: any2,
	}

	msg, err := newMsg(&pbv1.QBFTMsg{
		Type:              int64(qbft.MsgPrePrepare),
		ValueHash:         hash1[:],
		PreparedValueHash: hash2[:],
	}, nil, values)
	require.NoError(t, err)

	require.Equal(t, msg.Value(), hash1)
	require.Equal(t, msg.PreparedValue(), hash2)
	require.EqualValues(t, msg.values, values)
}

func TestPartialLegacyNewMsg(t *testing.T) {
	val1 := timestamppb.New(time.Time{})
	hash1, err := hashProto(val1)
	require.NoError(t, err)

	_, err = newMsg(&pbv1.QBFTMsg{
		Type: int64(qbft.MsgPrePrepare),
	}, []*pbv1.QBFTMsg{
		{
			Type:      int64(qbft.MsgPrePrepare),
			ValueHash: hash1[:],
		},
	}, make(map[[32]byte]*anypb.Any))
	require.ErrorContains(t, err, "value hash not found in values")
}

// randomMsg returns a random qbft message.
func randomMsg(t *testing.T) *pbv1.QBFTMsg {
	t.Helper()

	msgType := 1 + rand.Int63n(int64(qbft.MsgDecided))
	if msgType == 0 {
		msgType = 1
	}

	return &pbv1.QBFTMsg{
		Type:          msgType,
		Duty:          core.DutyToProto(core.Duty{Type: core.DutyType(rand.Int()), Slot: rand.Int63()}),
		PeerIdx:       rand.Int63(),
		Round:         rand.Int63(),
		PreparedRound: rand.Int63(),
		Signature:     nil,
	}
}
