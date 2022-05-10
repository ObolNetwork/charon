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
	ssz "github.com/ferranbt/fastssz"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/core/qbft"
)

var _ qbft.Msg[core.Duty, [32]byte] = msgImpl{} // Interface assertion

// newMsgImpl returns a new msgImpl.
func newMsgImpl(msg *pbv1.QBFTMsg, justification []*pbv1.QBFTMsg) (msgImpl, error) {
	// Do all possible error conversions first.

	valueHash, err := hashProto(msg.Value)
	if err != nil {
		return msgImpl{}, err
	}

	preparedValueHash, err := hashProto(msg.PreparedValue)
	if err != nil {
		return msgImpl{}, err
	}

	var justImpls []qbft.Msg[core.Duty, [32]byte]
	for _, msg := range justification {
		impl, err := newMsgImpl(msg, nil)
		if err != nil {
			return msgImpl{}, err
		}

		justImpls = append(justImpls, impl)
	}

	return msgImpl{
		msg:                msg,
		valueHash:          valueHash,
		preparedValueHash:  preparedValueHash,
		justification:      justification,
		justificationImpls: justImpls,
	}, nil
}

// msgImpl wraps *pbv1.ConsensusMsg and implements qbft.Msg[core.Duty, [32]byte].
type msgImpl struct {
	msg               *pbv1.QBFTMsg
	valueHash         [32]byte
	preparedValueHash [32]byte

	justification      []*pbv1.QBFTMsg
	justificationImpls []qbft.Msg[core.Duty, [32]byte]
}

func (m msgImpl) Type() qbft.MsgType {
	return qbft.MsgType(m.msg.Type)
}

func (m msgImpl) Instance() core.Duty {
	return core.DutyFromProto(m.msg.Duty)
}

func (m msgImpl) Source() int64 {
	return m.msg.PeerIdx
}

func (m msgImpl) Round() int64 {
	return m.msg.Round
}

func (m msgImpl) Value() [32]byte {
	return m.valueHash
}

func (m msgImpl) PreparedRound() int64 {
	return m.msg.PreparedRound
}

func (m msgImpl) PreparedValue() [32]byte {
	return m.preparedValueHash
}

func (m msgImpl) Justification() []qbft.Msg[core.Duty, [32]byte] {
	return m.justificationImpls
}

func (m msgImpl) ToConsensusMsg() *pbv1.ConsensusMsg {
	return &pbv1.ConsensusMsg{
		Msg:           m.msg,
		Justification: m.justification,
	}
}

// hashProto returns a ssz hash root of the proto message.
func hashProto(msg proto.Message) ([32]byte, error) {
	if msg == nil {
		return [32]byte{}, nil
	}

	hh := ssz.DefaultHasherPool.Get()
	defer ssz.DefaultHasherPool.Put(hh)

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
