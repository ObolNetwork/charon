// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state

import (
	"encoding/json"
	"os"

	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/cluster"
	statepb "github.com/obolnetwork/charon/cluster/statepb/v1"
)

// Load loads a cluster state from disk. It supports both legacy lock files and raw DAG files.
func Load(file string, lockCallback func(cluster.Lock) error) (*statepb.Cluster, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, errors.Wrap(err, "read file")
	}

	rawDAG := new(statepb.SignedMutationList)
	if err := proto.Unmarshal(b, rawDAG); err != nil {
		return loadLegacyLock(b, lockCallback)
	}

	return Materialise(rawDAG)
}

func loadLegacyLock(input []byte, lockCallback func(cluster.Lock) error) (*statepb.Cluster, error) {
	var lock cluster.Lock
	if err := json.Unmarshal(input, &lock); err != nil {
		return nil, errors.Wrap(err, "unmarshal legacy lock")
	}

	if lockCallback != nil {
		if err := lockCallback(lock); err != nil {
			return nil, err
		}
	}

	legacy, err := NewLegacyLock(lock)
	if err != nil {
		return nil, errors.Wrap(err, "create legacy lock")
	}

	return Materialise(&statepb.SignedMutationList{Mutations: []*statepb.SignedMutation{legacy}})
}
