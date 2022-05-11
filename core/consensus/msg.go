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
	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum/crypto"
	ssz "github.com/ferranbt/fastssz"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/core/qbft"
)

// newMsg returns a new msg.
func newMsg(pbMsg *pbv1.QBFTMsg, justification []*pbv1.QBFTMsg) (msg, error) {
	// Do all possible error conversions first.

	valueHash, err := hashProto(pbMsg.Value)
	if err != nil {
		return msg{}, err
	}

	preparedValueHash, err := hashProto(pbMsg.PreparedValue)
	if err != nil {
		return msg{}, err
	}

	var justImpls []qbft.Msg[core.Duty, [32]byte]
	for _, j := range justification {
		impl, err := newMsg(j, nil)
		if err != nil {
			return msg{}, err
		}

		justImpls = append(justImpls, impl)
	}

	return msg{
		msg:                 pbMsg,
		valueHash:           valueHash,
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
	return &pbv1.ConsensusMsg{
		Msg:           m.msg,
		Justification: m.justificationProtos,
	}
}

// hashProto returns a deterministic ssz hash root of the proto message.
func hashProto(msg proto.Message) ([32]byte, error) {
	if msg == nil {
		return [32]byte{}, nil
	}

	hh := ssz.DefaultHasherPool.Get()
	defer ssz.DefaultHasherPool.Put(hh)

	// Do deterministic marshalling.
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "marshal proto")
	}
	hh.PutBytes(b)

	hash, err := hh.HashRoot()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash proto")
	}

	return hash, nil
}

// verifyMsgSig returns true if the message with signed by the pubkey.
func verifyMsgSig(msg *pbv1.QBFTMsg, pubkey *ecdsa.PublicKey) (bool, error) {
	clone := proto.Clone(msg).(*pbv1.QBFTMsg)
	clone.Signature = nil

	hash, err := hashProto(clone)
	if err != nil {
		return false, err
	}

	actual, err := crypto.SigToPub(hash[:], msg.Signature)
	if err != nil {
		return false, errors.Wrap(err, "sig to pub")
	}

	return pubkey.Equal(actual), nil
}

// signMsg signs the proto message with the private key.
func signMsg(msg *pbv1.QBFTMsg, privkey *ecdsa.PrivateKey) (*pbv1.QBFTMsg, error) {
	msg.Signature = nil

	hash, err := hashProto(msg)
	if err != nil {
		return nil, err
	}

	sig, err := crypto.Sign(hash[:], privkey)
	if err != nil {
		return nil, errors.Wrap(err, "sign")
	}

	msg.Signature = sig

	return msg, nil
}

var _ qbft.Msg[core.Duty, [32]byte] = msg{} // Interface assertion
