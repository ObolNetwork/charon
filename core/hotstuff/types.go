// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff

import (
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
)

// ID uniquely identifies a replica. The first replica has ID = 1.
type ID uint64

const (
	InvalidID ID = 0
)

// ToIndex converts the ID to an index in a 0-based array.
func (id ID) ToIndex() int {
	return int(id - 1)
}

// View is the HotStuff view number. The first view has number 1.
type View uint64

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

// Phase defines the HotStuff phases.
type Phase uint64

const (
	PreparePhase Phase = iota
	PreCommitPhase
	CommitPhase
	DecidePhase
	TerminalPhase
)

var phaseLabels = map[Phase]string{
	PreparePhase:   "prepare",
	PreCommitPhase: "pre_commit",
	CommitPhase:    "commit",
	DecidePhase:    "decide",
	TerminalPhase:  "terminal",
}

func (p Phase) String() string {
	return phaseLabels[p]
}

func (p Phase) NextPhase() Phase {
	switch p {
	case PreparePhase:
		return PreCommitPhase
	case PreCommitPhase:
		return CommitPhase
	case CommitPhase:
		return DecidePhase
	default:
		return TerminalPhase
	}
}

// Hash represents a 32-byte hash.
type Hash [32]byte

// Value represents arbitrary value being replicated.
type Value []byte

// Msg represents a HotStuff protocol message.
type Msg struct {
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
	return &pbv1.HotStuffMsg{
		Type:      uint64(msg.Type),
		View:      uint64(msg.View),
		Vote:      msg.Vote,
		Value:     msg.Value,
		ValueHash: msg.ValueHash[:],
		Signature: msg.Signature,
		Qc:        msg.QC.ToProto(),
	}
}

func ProtoToMsg(protoMsg *pbv1.HotStuffMsg) *Msg {
	msg := &Msg{
		Type:      MsgType(protoMsg.Type),
		View:      View(protoMsg.View),
		Vote:      protoMsg.Vote,
		Value:     protoMsg.Value,
		Signature: protoMsg.Signature,
		QC:        ProtoToQC(protoMsg.Qc),
	}

	copy(msg.ValueHash[:], protoMsg.ValueHash)

	return msg
}

func ProtoToQC(protoQC *pbv1.HotStuffQC) *QC {
	if protoQC == nil {
		return nil
	}

	qc := &QC{
		Type:       MsgType(protoQC.Type),
		View:       View(protoQC.View),
		ValueHash:  Hash(protoQC.ValueHash),
		Signatures: protoQC.Signatures,
	}

	copy(qc.ValueHash[:], protoQC.ValueHash)

	return qc
}
