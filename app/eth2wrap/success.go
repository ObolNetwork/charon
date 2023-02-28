// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// isSyncStateOk returns tue if the sync state is not syncing.
func isSyncStateOk(s *apiv1.SyncState) bool {
	return !s.IsSyncing
}

// isAggregateAttestationOk returns true if the aggregate attestation is not nil (which can happen if the subscription wasn't successful).
func isAggregateAttestationOk(att *phase0.Attestation) bool {
	return att != nil
}
