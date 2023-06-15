// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state

import (
	"encoding/json"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/cluster"
	pbv1 "github.com/obolnetwork/charon/cluster/statepb/v1"
)

func Hash(signed *pbv1.SignedMutation) ([32]byte, error) {
	// Return legacy lock hash if this is a legacy lock mutation.
	if signed.Mutation.Type == string(TypeLegacyLock) {
		legacyLock := new(pbv1.LegacyLock)
		if err := signed.Mutation.Data.UnmarshalTo(legacyLock); err != nil {
			return [32]byte{}, errors.Wrap(err, "mutation data to legacy lock")
		}

		var lock cluster.Lock
		if err := json.Unmarshal(legacyLock.Json, &lock); err != nil {
			return [32]byte{}, errors.Wrap(err, "unmarshal lock")
		}

		if len(lock.LockHash) != 32 {
			return [32]byte{}, errors.New("invalid lock hash")
		}

		return [32]byte(lock.LockHash), nil
	}

	// Otherwise return the hash of the signed mutation.
	return hashSignedMutation(signed)
}

// Transform returns a transformed cluster state by applying this mutation.
func Transform(cluster Cluster, signed *pbv1.SignedMutation) (Cluster, error) {
	typ := MutationType(signed.Mutation.Type)

	if !typ.Valid() {
		return cluster, errors.New("invalid mutation type")
	}

	return typ.Transform(cluster, signed)
}
