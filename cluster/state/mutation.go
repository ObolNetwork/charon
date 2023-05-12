// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state

import (
	"encoding/json"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/cluster"
)

// MutationType represents the type of a mutation.
type MutationType string

// Valid returns true if the mutation type is valid.
func (t MutationType) Valid() bool {
	_, ok := mutationDefs[t]
	return ok
}

// String returns the name of the mutation type.
func (t MutationType) String() string {
	return string(t)
}

// Unmarshal returns a new unmarshalled mutation data from the input bytes.
func (t MutationType) Unmarshal(input []byte) (MutationData, error) {
	return mutationDefs[t].UnmarshalFunc(input)
}

// Transform returns a transformed cluster state with the given mutation.
func (t MutationType) Transform(cluster Cluster, signed SignedMutation) (Cluster, error) {
	// TODO(corver): Verify signature

	return mutationDefs[t].TransformFunc(cluster, signed)
}

const (
	TypeUnknown       MutationType = ""
	TypeLegacyLock    MutationType = "dv/legacy_lock/v0.0.1"
	TypeNodeApproval  MutationType = "dv/node_approval/v0.0.1"
	TypeNodeApprovals MutationType = "dv/node_approvals/v0.0.1"
)

var mutationDefs = map[MutationType]struct {
	UnmarshalFunc func(input []byte) (MutationData, error)
	TransformFunc func(Cluster, SignedMutation) (Cluster, error)
}{
	TypeLegacyLock: {
		UnmarshalFunc: func(input []byte) (MutationData, error) {
			var lock cluster.Lock
			if err := json.Unmarshal(input, &lock); err != nil {
				return nil, errors.Wrap(err, "unmarshal lock")
			}

			return lockWrapper{lock}, nil
		},
		TransformFunc: transformLegacyLock,
	},
}
