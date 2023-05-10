// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state

import "github.com/obolnetwork/charon/cluster"

// MutationType represents the type of a mutation.
type MutationType string

func (t MutationType) String() string {
	return string(t)
}

func (t MutationType) DataType() any {
	return mutationDefs[t].DataType
}

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
	DataType      any
	TransformFunc func(Cluster, SignedMutation) (Cluster, error)
}{
	TypeLegacyLock: {
		DataType:      cluster.Lock{},
		TransformFunc: transformLegacyLock,
	},
}
