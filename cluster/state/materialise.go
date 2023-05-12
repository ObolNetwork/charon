// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state

import "github.com/obolnetwork/charon/app/errors"

// Materialise transforms a raw DAG and returns the resulting cluster state.
func Materialise(rawDAG RawDAG) (Cluster, error) {
	if len(rawDAG) == 0 {
		return Cluster{}, errors.New("empty raw DAG")
	}

	var (
		cluster Cluster
		err     error
	)
	for _, signed := range rawDAG {
		cluster, err = signed.Transform(cluster)
		if err != nil {
			return Cluster{}, err
		}
	}

	// Cluster hash is the hash of the first mutation.
	cluster.Hash, err = rawDAG[0].Hash()
	if err != nil {
		return Cluster{}, errors.Wrap(err, "calculate cluster hash")
	}

	return cluster, nil
}
