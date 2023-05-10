// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state

import (
	"encoding/json"
	"time"

	ssz "github.com/ferranbt/fastssz"
)

//go:generate genssz

// RawDAG is a list of mutations that constitute the raw cluster state DAG.
type RawDAG []Mutation

// rootHasher indicates that a type can be hashed with a ssz.HashWalker.
type rootHasher interface {
	HashTreeRootWith(hw ssz.HashWalker) error
}

// MutationData is the interface that all mutation data types must implement.
type MutationData interface {
	rootHasher
	json.Marshaler
}

// Mutation mutates the cluster state.
type Mutation struct {
	// Parent is the hash of the parent mutation.
	Parent [32]byte `ssz:"Bytes32"`
	// Type is the type of mutation.
	Type MutationType `ssz:"ByteList[64]"` // TODO(corver): Make this a numbered enum maybe (instead of a string)?.
	// Timestamp of the mutation.
	Timestamp time.Time `ssz:"uint64"`
	// Data is the data of the mutation.
	Data MutationData `ssz:"Composite"`
}

// SignedMutation is a signed mutation.
type SignedMutation struct {
	// Mutation is the mutation.
	Mutation Mutation `ssz:"Composite"`
	// Hash is the SSZ root calculated from the mutation.
	Hash [32]byte `ssz:"Bytes32"`
	// Signer is the identity (public key) of the signer.
	Signer []byte `ssz:"ByteList[256]"`
	// Signature is the signature of the mutation.
	Signature []byte `ssz:"ByteList[256]"`
}
