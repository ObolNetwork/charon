// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state

import (
	"github.com/obolnetwork/charon/app/errors"
	statepb "github.com/obolnetwork/charon/cluster/statepb/v1"
)

// Materialise transforms a raw DAG and returns the resulting cluster state.
func Materialise(rawDAG *statepb.SignedMutationList) (*statepb.Cluster, error) {
	if rawDAG == nil || len(rawDAG.Mutations) == 0 {
		return nil, errors.New("empty raw DAG")
	}

	var (
		cluster = new(statepb.Cluster)
		err     error
	)
	for _, signed := range rawDAG.Mutations {
		cluster, err = Transform(cluster, signed)
		if err != nil {
			return nil, err
		}
	}

	// Cluster hash is the hash of the first mutation.
	cluster.Hash, err = Hash(rawDAG.Mutations[0])
	if err != nil {
		return nil, errors.Wrap(err, "calculate cluster hash")
	}

	return cluster, nil
}
