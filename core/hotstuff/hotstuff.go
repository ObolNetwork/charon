// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff

import (
	"context"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/obolnetwork/charon/core"
)

//go:generate mockery --name=Transport --output=mocks --outpkg=mocks --case=underscore
//go:generate mockery --name=Cluster --output=mocks --outpkg=mocks --case=underscore

// ID uniquely identifies a replica. The first replica has ID = 0.
type ID uint64

// View is the HotStuff view number. The first view has number 1.
type View uint64

// Transport defines replica's transport layer.
type Transport interface {
	// Broadcast sends a message to all replicas, including itself.
	Broadcast(ctx context.Context, msg *Msg) error

	// SendTo sends a message to the specified replica, typically to the leader.
	SendTo(ctx context.Context, id ID, msg *Msg) error
}

// Cluster defines the Byzantine cluster configuration.
type Cluster interface {
	// Leader returns the deterministic leader ID for the given view.
	Leader(duty core.Duty, view View) ID

	// PublicKeyToID returns the replica ID for the given public key.
	PublicKeyToID(pubKey *k1.PublicKey) (ID, error)

	// HasQuorum returns true if the given public keys meet the threshold.
	HasQuorum(pubKeys []*k1.PublicKey) bool

	// Threshold returns the Byzantine quorum threshold.
	Threshold() uint

	// MaxView returns the maximum view number.
	// The number determines the number of views before stopping the protocol.
	MaxView() View

	// PhaseTimeout returns the timeout for each phase.
	PhaseTimeout() time.Duration
}

// DecidedFunc is a callback function invoked when a value is decided.
type DecidedFunc func(value Value, duty core.Duty, view View)

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
