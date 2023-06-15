// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state

import (
	"github.com/obolnetwork/charon/app/errors"
	pbv1 "github.com/obolnetwork/charon/cluster/statepb/v1"
)

// Materialise transforms a raw DAG and returns the resulting cluster state.
func Materialise(rawDAG *pbv1.SignedMutationList) (Cluster, error) {
	if rawDAG == nil || len(rawDAG.Mutations) == 0 {
		return Cluster{}, errors.New("empty raw DAG")
	}

	var (
		cluster Cluster
		err     error
	)
	for _, signed := range rawDAG.Mutations {
		cluster, err = Transform(cluster, signed)
		if err != nil {
			return Cluster{}, err
		}
	}

	// Cluster hash is the hash of the first mutation.
	cluster.Hash, err = Hash(rawDAG.Mutations[0])
	if err != nil {
		return Cluster{}, errors.Wrap(err, "calculate cluster hash")
	}

	return cluster, nil
}
