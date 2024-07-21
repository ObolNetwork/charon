// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package manifest

import (
	"encoding/json"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/cluster"
	manifestpb "github.com/obolnetwork/charon/cluster/manifestpb/v1"
)

func Hash(signed *manifestpb.SignedMutation) ([]byte, error) {
	// Return legacy lock hash if this is a legacy lock mutation.
	if signed.GetMutation().GetType() == string(TypeLegacyLock) {
		legacyLock := new(manifestpb.LegacyLock)
		if err := signed.GetMutation().GetData().UnmarshalTo(legacyLock); err != nil {
			return nil, errors.Wrap(err, "mutation data to legacy lock")
		}

		var lock cluster.Lock
		if err := json.Unmarshal(legacyLock.GetJson(), &lock); err != nil {
			return nil, errors.Wrap(err, "unmarshal lock")
		}

		if len(lock.LockHash) != 32 {
			return nil, errors.New("invalid lock hash")
		}

		return lock.LockHash, nil
	}

	// Otherwise return the hash of the signed mutation.
	return hashSignedMutation(signed)
}

// Transform returns a transformed cluster manifest by applying this mutation.
func Transform(cluster *manifestpb.Cluster, signed *manifestpb.SignedMutation) (*manifestpb.Cluster, error) {
	if cluster == nil {
		return nil, errors.New("nil cluster")
	}

	typ := MutationType(signed.GetMutation().GetType())

	if !typ.Valid() {
		return cluster, errors.New("invalid mutation type")
	}

	return typ.Transform(cluster, signed)
}
