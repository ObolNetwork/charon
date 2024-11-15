// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff

import (
	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
)

// MsgType defines the HotStuff message types.
type MsgType uint64

// Note that message type ordering MUST not change, since it breaks backwards compatibility.
const (
	MsgNewView MsgType = iota
	MsgPrepare
	MsgPreCommit
	MsgCommit
	MsgDecide
)

var typeLabels = map[MsgType]string{
	MsgNewView:   "new_view",
	MsgPrepare:   "prepare",
	MsgPreCommit: "pre_commit",
	MsgCommit:    "commit",
	MsgDecide:    "decide",
}

func (t MsgType) String() string {
	return typeLabels[t]
}

func (t MsgType) NextMsgType() MsgType {
	switch t {
	case MsgNewView:
		return MsgPrepare
	case MsgPrepare:
		return MsgPreCommit
	case MsgPreCommit:
		return MsgCommit
	case MsgCommit:
		return MsgDecide
	default:
		return MsgNewView
	}
}

// Hash represents a 32-byte hash.
type Hash [32]byte

// Value represents arbitrary value being replicated.
type Value []byte

// Msg represents a HotStuff protocol message.
type Msg struct {
	Duty      core.Duty
	Type      MsgType
	View      View
	Value     Value
	ValueHash Hash
	Vote      bool
	Signature []byte
	QC        *QC
}

// QC represents a quorum certificate.
type QC struct {
	Type       MsgType
	View       View
	ValueHash  Hash
	Signatures [][]byte
}

func (qc *QC) ToProto() *pbv1.HotStuffQC {
	if qc == nil {
		return nil
	}

	return &pbv1.HotStuffQC{
		Type:       uint64(qc.Type),
		View:       uint64(qc.View),
		ValueHash:  qc.ValueHash[:],
		Signatures: qc.Signatures,
	}
}

func (msg *Msg) ToProto() *pbv1.HotStuffMsg {
	hasQC := true
	qc := msg.QC.ToProto()
	if msg.QC == nil {
		hasQC = false
		qc = &pbv1.HotStuffQC{}
	}

	return &pbv1.HotStuffMsg{
		Duty: &pbv1.Duty{
			Type: int32(msg.Duty.Type),
			Slot: msg.Duty.Slot,
		},
		Type:      uint64(msg.Type),
		View:      uint64(msg.View),
		Vote:      msg.Vote,
		Value:     msg.Value,
		ValueHash: msg.ValueHash[:],
		Signature: msg.Signature,
		Qc:        qc,
		HasQc:     hasQC,
	}
}

func ProtoToMsg(protoMsg *pbv1.HotStuffMsg) *Msg {
	var qc *QC
	if protoMsg.GetHasQc() {
		qc = ProtoToQC(protoMsg.GetQc())
	}

	msg := &Msg{
		Duty:      ProtoToDuty(protoMsg.GetDuty()),
		Type:      MsgType(protoMsg.GetType()),
		View:      View(protoMsg.GetView()),
		Vote:      protoMsg.GetVote(),
		Value:     protoMsg.GetValue(),
		Signature: protoMsg.GetSignature(),
		QC:        qc,
	}

	copy(msg.ValueHash[:], protoMsg.GetValueHash())

	return msg
}

func ProtoToQC(protoQC *pbv1.HotStuffQC) *QC {
	if protoQC == nil {
		return nil
	}

	qc := &QC{
		Type:       MsgType(protoQC.GetType()),
		View:       View(protoQC.GetView()),
		Signatures: protoQC.GetSignatures(),
	}

	copy(qc.ValueHash[:], protoQC.GetValueHash())

	return qc
}

func ProtoToDuty(protoDuty *pbv1.Duty) core.Duty {
	return core.Duty{
		Type: core.DutyType(protoDuty.Type),
		Slot: protoDuty.Slot,
	}
}
