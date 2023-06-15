// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state

import (
	statepb "github.com/obolnetwork/charon/cluster/statepb/v1"
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

// Transform returns a transformed cluster state with the given mutation.
func (t MutationType) Transform(cluster *statepb.Cluster, signed *statepb.SignedMutation) (*statepb.Cluster, error) {
	return mutationDefs[t].TransformFunc(cluster, signed)
}

const (
	TypeUnknown       MutationType = ""
	TypeLegacyLock    MutationType = "dv/legacy_lock/v0.0.1"
	TypeNodeApproval  MutationType = "dv/node_approval/v0.0.1"
	TypeNodeApprovals MutationType = "dv/node_approvals/v0.0.1"
	TypeGenValidators MutationType = "dv/gen_validators/v0.0.1"
	TypeAddValidators MutationType = "dv/add_validators/v0.0.1"
)

type mutationDef struct {
	TransformFunc func(*statepb.Cluster, *statepb.SignedMutation) (*statepb.Cluster, error)
}

var mutationDefs = make(map[MutationType]mutationDef)

// init is required to populate the mutation definition map since
// static compile-time results in initialization cycle.
//
//nolint:gochecknoinits // required to avoid cycles
func init() {
	mutationDefs[TypeLegacyLock] = mutationDef{
		TransformFunc: transformLegacyLock,
	}

	mutationDefs[TypeNodeApproval] = mutationDef{
		TransformFunc: func(c *statepb.Cluster, signed *statepb.SignedMutation) (*statepb.Cluster, error) {
			return c, verifyNodeApproval(signed)
		},
	}

	mutationDefs[TypeNodeApprovals] = mutationDef{
		TransformFunc: transformNodeApprovals,
	}

	mutationDefs[TypeGenValidators] = mutationDef{
		TransformFunc: transformGenValidators,
	}

	mutationDefs[TypeAddValidators] = mutationDef{
		TransformFunc: transformAddValidators,
	}
}
