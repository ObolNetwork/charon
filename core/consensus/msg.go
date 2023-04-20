// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

// newMsg returns a new msg.
func newMsg(pbMsg *pbv1.QBFTMsg, justification []*pbv1.QBFTMsg, values map[[32]byte]*anypb.Any) (msg, error) {
	if !qbft.MsgType(pbMsg.GetType()).Valid() {
		return msg{}, errors.New("invalid message type")
	}

	// Do all possible error conversions first.
	var (
		valueHash         [32]byte
		preparedValueHash [32]byte
	)

	if hash, ok := toHash32(pbMsg.ValueHash); ok {
		valueHash = hash
		if _, ok := values[valueHash]; !ok {
			return msg{}, errors.New("value hash not found in values")
		}
	}

	if hash, ok := toHash32(pbMsg.PreparedValueHash); ok {
		preparedValueHash = hash
		if _, ok := values[preparedValueHash]; !ok {
			return msg{}, errors.New("prepared value hash not found in values")
		}
	}

	var justImpls []qbft.Msg[core.Duty, [32]byte]
	for _, j := range justification {
		if !qbft.MsgType(j.GetType()).Valid() {
			return msg{}, errors.New("invalid message type")
		}

		impl, err := newMsg(j, nil, values)
		if err != nil {
			return msg{}, err
		}

		justImpls = append(justImpls, impl)
	}

	return msg{
		msg:                 pbMsg,
		valueHash:           valueHash,
		values:              values,
		preparedValueHash:   preparedValueHash,
		justificationProtos: justification,
		justification:       justImpls,
	}, nil
}

// msg wraps *pbv1.QBFTMsg and justifications and implements qbft.Msg[core.Duty, [32]byte].
type msg struct {
	msg               *pbv1.QBFTMsg
	valueHash         [32]byte
	preparedValueHash [32]byte
	values            map[[32]byte]*anypb.Any

	justificationProtos []*pbv1.QBFTMsg
	justification       []qbft.Msg[core.Duty, [32]byte]
}

func (m msg) Type() qbft.MsgType {
	return qbft.MsgType(m.msg.Type)
}

func (m msg) Instance() core.Duty {
	return core.DutyFromProto(m.msg.Duty)
}

func (m msg) Source() int64 {
	return m.msg.PeerIdx
}

func (m msg) Round() int64 {
	return m.msg.Round
}

func (m msg) Value() [32]byte {
	return m.valueHash
}

func (m msg) PreparedRound() int64 {
	return m.msg.PreparedRound
}

func (m msg) PreparedValue() [32]byte {
	return m.preparedValueHash
}

func (m msg) Justification() []qbft.Msg[core.Duty, [32]byte] {
	return m.justification
}

func (m msg) ToConsensusMsg() *pbv1.ConsensusMsg {
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

// verifyMsgSig returns true if the message was signed by pubkey.
func verifyMsgSig(msg *pbv1.QBFTMsg, pubkey *k1.PublicKey) (bool, error) {
	if msg.Signature == nil {
		return false, errors.New("empty signature")
	}

	clone := proto.Clone(msg).(*pbv1.QBFTMsg)
	clone.Signature = nil
	hash, err := hashProto(clone)
	if err != nil {
		return false, err
	}

	recovered, err := k1util.Recover(hash[:], msg.Signature)
	if err != nil {
		return false, errors.Wrap(err, "recover pubkey")
	}

	return recovered.IsEqual(pubkey), nil
}

// signMsg returns a copy of the proto message with a populated signature signed by the provided private key.
func signMsg(msg *pbv1.QBFTMsg, privkey *k1.PrivateKey) (*pbv1.QBFTMsg, error) {
	clone := proto.Clone(msg).(*pbv1.QBFTMsg)
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

var _ qbft.Msg[core.Duty, [32]byte] = msg{} // Interface assertion
