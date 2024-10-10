// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package qbft

import (
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	ssz "github.com/ferranbt/fastssz"
	"golang.org/x/exp/rand"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/core/qbft"
)

// NewRandomMsgForT returns a random qbft message.
func NewRandomMsgForT(t *testing.T) *pbv1.QBFTMsg {
	t.Helper()

	msgType := 1 + rand.Int63n(int64(qbft.MsgDecided))
	if msgType == 0 {
		msgType = 1
	}

	return &pbv1.QBFTMsg{
		Type:          msgType,
		Duty:          core.DutyToProto(core.Duty{Type: core.DutyType(rand.Int()), Slot: rand.Uint64()}),
		PeerIdx:       rand.Int63(),
		Round:         rand.Int63(),
		PreparedRound: rand.Int63(),
		Signature:     nil,
	}
}

// NewMsg returns a new QBFT Msg.
func NewMsg(pbMsg *pbv1.QBFTMsg, justification []*pbv1.QBFTMsg, values map[[32]byte]*anypb.Any) (Msg, error) {
	if pbMsg == nil {
		return Msg{}, errors.New("nil qbft message")
	}

	// Do all possible error conversions first.
	var (
		valueHash         [32]byte
		preparedValueHash [32]byte
	)

	if hash, ok := toHash32(pbMsg.GetValueHash()); ok {
		valueHash = hash
		if _, ok := values[valueHash]; !ok {
			return Msg{}, errors.New("value hash not found in values")
		}
	}

	if hash, ok := toHash32(pbMsg.GetPreparedValueHash()); ok {
		preparedValueHash = hash
		if _, ok := values[preparedValueHash]; !ok {
			return Msg{}, errors.New("prepared value hash not found in values")
		}
	}

	var justImpls []qbft.Msg[core.Duty, [32]byte]
	for _, j := range justification {
		impl, err := NewMsg(j, nil, values)
		if err != nil {
			return Msg{}, err
		}

		justImpls = append(justImpls, impl)
	}

	return Msg{
		msg:                 pbMsg,
		valueHash:           valueHash,
		values:              values,
		preparedValueHash:   preparedValueHash,
		justificationProtos: justification,
		justification:       justImpls,
	}, nil
}

// Msg wraps *pbv1.QBFTMsg and justifications and implements qbft.Msg[core.Duty, [32]byte].
type Msg struct {
	msg               *pbv1.QBFTMsg
	valueHash         [32]byte
	preparedValueHash [32]byte
	values            map[[32]byte]*anypb.Any

	justificationProtos []*pbv1.QBFTMsg
	justification       []qbft.Msg[core.Duty, [32]byte]
}

func (m Msg) Type() qbft.MsgType {
	return qbft.MsgType(m.msg.GetType())
}

func (m Msg) Instance() core.Duty {
	return core.DutyFromProto(m.msg.GetDuty())
}

func (m Msg) Source() int64 {
	return m.msg.GetPeerIdx()
}

func (m Msg) Round() int64 {
	return m.msg.GetRound()
}

func (m Msg) Value() [32]byte {
	return m.valueHash
}

func (m Msg) Values() map[[32]byte]*anypb.Any {
	return m.values
}

func (m Msg) Msg() *pbv1.QBFTMsg {
	return m.msg
}

func (m Msg) PreparedRound() int64 {
	return m.msg.GetPreparedRound()
}

func (m Msg) PreparedValue() [32]byte {
	return m.preparedValueHash
}

func (m Msg) Justification() []qbft.Msg[core.Duty, [32]byte] {
	return m.justification
}

func (m Msg) ToConsensusMsg() *pbv1.ConsensusMsg {
	var values []*anypb.Any
	for _, v := range m.values {
		values = append(values, v)
	}

	return &pbv1.ConsensusMsg{
		Msg:           m.msg,
		Justification: m.justificationProtos,
		Values:        values,
	}
}

// HashProto returns a deterministic ssz hash root of the proto message.
// It is the same logic as that used by the priority package.
func HashProto(msg proto.Message) ([32]byte, error) {
	if _, ok := msg.(*anypb.Any); ok {
		return [32]byte{}, errors.New("cannot hash any proto, must hash inner value")
	}

	hh := ssz.DefaultHasherPool.Get()
	defer ssz.DefaultHasherPool.Put(hh)

	index := hh.Index()

	// Do deterministic marshalling.
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "marshal proto")
	}
	hh.PutBytes(b)

	hh.Merkleize(index)

	hash, err := hh.HashRoot()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash proto")
	}

	return hash, nil
}

// VerifyMsgSig returns true if the message was signed by pubkey.
func VerifyMsgSig(msg *pbv1.QBFTMsg, pubkey *k1.PublicKey) (bool, error) {
	if msg.Signature == nil {
		return false, errors.New("empty signature")
	}

	clone, ok := proto.Clone(msg).(*pbv1.QBFTMsg)
	if !ok {
		return false, errors.New("type assert qbft msg")
	}
	clone.Signature = nil
	hash, err := HashProto(clone)
	if err != nil {
		return false, err
	}

	recovered, err := k1util.Recover(hash[:], msg.GetSignature())
	if err != nil {
		return false, errors.Wrap(err, "recover pubkey")
	}

	return recovered.IsEqual(pubkey), nil
}

// SignMsg returns a copy of the proto message with a populated signature signed by the provided private key.
func SignMsg(msg *pbv1.QBFTMsg, privkey *k1.PrivateKey) (*pbv1.QBFTMsg, error) {
	clone, ok := proto.Clone(msg).(*pbv1.QBFTMsg)
	if !ok {
		return nil, errors.New("type assert qbft msg")
	}
	clone.Signature = nil

	hash, err := HashProto(clone)
	if err != nil {
		return nil, err
	}

	clone.Signature, err = k1util.Sign(privkey, hash[:])
	if err != nil {
		return nil, errors.Wrap(err, "sign")
	}

	return clone, nil
}

// toHash32 returns the value as a 32-byte hash and true or false if not a valid hash.
func toHash32(val []byte) ([32]byte, bool) {
	if len(val) != 32 {
		return [32]byte{}, false // Nil hash
	}

	resp := [32]byte(val)
	if resp == [32]byte{} {
		return [32]byte{}, false // Zero hash
	}

	return resp, true
}

var _ qbft.Msg[core.Duty, [32]byte] = Msg{} // Interface assertion
