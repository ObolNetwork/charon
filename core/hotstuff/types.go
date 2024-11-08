// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff

import "github.com/obolnetwork/charon/tbls"

// ID uniquely identifies a replica. The first replica has ID = 0.
type ID uint64

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

// Msg represents a HotStuff protocol message.
type Msg struct {
	Sender  ID
	Type    MsgType
	View    View
	Value   string
	Vote    bool
	ParSig  []byte
	Justify *QC
}

// QC represents a quorum certificate.
type QC struct {
	Type  MsgType
	View  View
	Value string
	Sig   []byte
}

func (qc *QC) Verify(pubKey tbls.PublicKey) error {
	if qc == nil {
		return nil
	}

	return Verify(pubKey, qc.Type, qc.View, qc.Value, qc.Sig)
}
