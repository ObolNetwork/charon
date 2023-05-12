// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state

import (
	"encoding/json"
	"time"

	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
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

func (m Mutation) MarshalJSON() ([]byte, error) {
	data, err := json.Marshal(m.Data)
	if err != nil {
		return nil, errors.Wrap(err, "marshal mutation data")
	}

	b, err := json.Marshal(mutationJSON{
		Parent:    m.Parent[:],
		Type:      m.Type,
		Timestamp: m.Timestamp.UTC().Format(time.RFC3339),
		Data:      data,
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal mutation")
	}

	return b, nil
}

func (m *Mutation) UnmarshalJSON(input []byte) error {
	var raw mutationJSON
	if err := json.Unmarshal(input, &raw); err != nil {
		return errors.Wrap(err, "unmarshal mutation")
	}

	if !raw.Type.Valid() {
		return errors.New("invalid mutation type")
	}

	data, err := raw.Type.Unmarshal(raw.Data)
	if err != nil {
		return errors.Wrap(err, "unmarshal mutation data")
	}

	timestamp, err := time.Parse(time.RFC3339, raw.Timestamp)
	if err != nil {
		return errors.Wrap(err, "parse mutation timestamp")
	}

	if len(raw.Parent) != 32 {
		return errors.New("invalid parent hash")
	}

	m.Parent = [32]byte(raw.Parent)
	m.Type = raw.Type
	m.Timestamp = timestamp
	m.Data = data

	return nil
}

type mutationJSON struct {
	Parent    ethHex          `json:"parent"`
	Type      MutationType    `json:"type"`
	Timestamp string          `json:"timestamp"`
	Data      json.RawMessage `json:"data"`
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

func (m SignedMutation) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(signedMutationJSON{
		Mutation:  m.Mutation,
		Hash:      m.Hash[:],
		Signer:    m.Signer,
		Signature: m.Signature,
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal signed mutation")
	}

	return b, nil
}

func (m *SignedMutation) UnmarshalJSON(input []byte) error {
	var raw signedMutationJSON
	if err := json.Unmarshal(input, &raw); err != nil {
		return errors.Wrap(err, "unmarshal signed mutation")
	}

	if len(raw.Hash) != 32 {
		return errors.New("invalid hash")
	}

	m.Mutation = raw.Mutation
	m.Hash = [32]byte(raw.Hash)
	m.Signer = raw.Signer
	m.Signature = raw.Signature

	return nil
}

type signedMutationJSON struct {
	Mutation  Mutation `json:"mutation"`
	Hash      ethHex   `json:"hash"`
	Signer    ethHex   `json:"signer"`
	Signature ethHex   `json:"signature"`
}
