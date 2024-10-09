// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus

import (
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	ssz "github.com/ferranbt/fastssz"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/core/qbft"
)

// newQBFTMsg returns a new QBFT msg.
func newQBFTMsg(pbMsg *pbv1.QBFTMsg, justification []*pbv1.QBFTMsg, values map[[32]byte]*anypb.Any) (qbftMsg, error) {
	if pbMsg == nil {
		return qbftMsg{}, errors.New("nil qbft message")
	}

	// Do all possible error conversions first.
	var (
		valueHash         [32]byte
		preparedValueHash [32]byte
	)

	if hash, ok := toHash32(pbMsg.GetValueHash()); ok {
		valueHash = hash
		if _, ok := values[valueHash]; !ok {
			return qbftMsg{}, errors.New("value hash not found in values")
		}
	}

	if hash, ok := toHash32(pbMsg.GetPreparedValueHash()); ok {
		preparedValueHash = hash
		if _, ok := values[preparedValueHash]; !ok {
			return qbftMsg{}, errors.New("prepared value hash not found in values")
		}
	}

	var justImpls []qbft.Msg[core.Duty, [32]byte]
	for _, j := range justification {
		impl, err := newQBFTMsg(j, nil, values)
		if err != nil {
			return qbftMsg{}, err
		}

		justImpls = append(justImpls, impl)
	}

	return qbftMsg{
		msg:                 pbMsg,
		valueHash:           valueHash,
		values:              values,
		preparedValueHash:   preparedValueHash,
		justificationProtos: justification,
		justification:       justImpls,
	}, nil
}

// qbftMsg wraps *pbv1.QBFTMsg and justifications and implements qbft.Msg[core.Duty, [32]byte].
type qbftMsg struct {
	msg               *pbv1.QBFTMsg
	valueHash         [32]byte
	preparedValueHash [32]byte
	values            map[[32]byte]*anypb.Any

	justificationProtos []*pbv1.QBFTMsg
	justification       []qbft.Msg[core.Duty, [32]byte]
}

func (m qbftMsg) Type() qbft.MsgType {
	return qbft.MsgType(m.msg.GetType())
}

func (m qbftMsg) Instance() core.Duty {
	return core.DutyFromProto(m.msg.GetDuty())
}

func (m qbftMsg) Source() int64 {
	return m.msg.GetPeerIdx()
}

func (m qbftMsg) Round() int64 {
	return m.msg.GetRound()
}

func (m qbftMsg) Value() [32]byte {
	return m.valueHash
}

func (m qbftMsg) PreparedRound() int64 {
	return m.msg.GetPreparedRound()
}

func (m qbftMsg) PreparedValue() [32]byte {
	return m.preparedValueHash
}

func (m qbftMsg) Justification() []qbft.Msg[core.Duty, [32]byte] {
	return m.justification
}

func (m qbftMsg) ToConsensusMsg() *pbv1.ConsensusMsg {
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

// hashProto returns a deterministic ssz hash root of the proto message.
// It is the same logic as that used by the priority package.
func hashProto(msg proto.Message) ([32]byte, error) {
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

// verifyQBFTMsgSig returns true if the message was signed by pubkey.
func verifyQBFTMsgSig(msg *pbv1.QBFTMsg, pubkey *k1.PublicKey) (bool, error) {
	if msg.Signature == nil {
		return false, errors.New("empty signature")
	}

	clone, ok := proto.Clone(msg).(*pbv1.QBFTMsg)
	if !ok {
		return false, errors.New("type assert qbft msg")
	}
	clone.Signature = nil
	hash, err := hashProto(clone)
	if err != nil {
		return false, err
	}

	recovered, err := k1util.Recover(hash[:], msg.GetSignature())
	if err != nil {
		return false, errors.Wrap(err, "recover pubkey")
	}

	return recovered.IsEqual(pubkey), nil
}

// signQBFTMsg returns a copy of the proto message with a populated signature signed by the provided private key.
func signQBFTMsg(msg *pbv1.QBFTMsg, privkey *k1.PrivateKey) (*pbv1.QBFTMsg, error) {
	clone, ok := proto.Clone(msg).(*pbv1.QBFTMsg)
	if !ok {
		return nil, errors.New("type assert qbft msg")
	}
	clone.Signature = nil

	hash, err := hashProto(clone)
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

var _ qbft.Msg[core.Duty, [32]byte] = qbftMsg{} // Interface assertion
