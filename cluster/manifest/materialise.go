// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package manifest

import (
	"github.com/obolnetwork/charon/app/errors"
	manifestpb "github.com/obolnetwork/charon/cluster/manifestpb/v1"
)

// Materialise transforms a raw DAG and returns the resulting cluster manifest.
func Materialise(rawDAG *manifestpb.SignedMutationList) (*manifestpb.Cluster, error) {
	if rawDAG == nil || len(rawDAG.GetMutations()) == 0 {
		return nil, errors.New("empty raw DAG")
	}

	var (
		cluster = new(manifestpb.Cluster)
		err     error
	)
	for _, signed := range rawDAG.GetMutations() {
		cluster, err = Transform(cluster, signed)
		if err != nil {
			return nil, err
		}
	}

	// InitialMutationHash is the hash of the first mutation.
	cluster.InitialMutationHash, err = Hash(rawDAG.GetMutations()[0])
	if err != nil {
		return nil, errors.Wrap(err, "calculate initial hash")
	}

	// LatestMutationHash is the hash of the last mutation.
	cluster.LatestMutationHash, err = Hash(rawDAG.GetMutations()[len(rawDAG.GetMutations())-1])
	if err != nil {
		return nil, errors.Wrap(err, "calculate latest hash")
	}

	return cluster, nil
}
