// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state

// Materialise transforms a raw DAG and returns the resulting cluster state.
func Materialise(rawDAG RawDAG) (Cluster, error) {
	var cluster Cluster
	for _, signed := range rawDAG {
		var err error
		cluster, err = signed.Transform(cluster)
		if err != nil {
			return Cluster{}, err
		}
	}

	return cluster, nil
}
