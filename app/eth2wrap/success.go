// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
)

// isSyncStateOk returns true if the sync state is not syncing.
func isSyncStateOk(resp *eth2api.Response[*eth2v1.SyncState]) bool {
	return !resp.Data.IsSyncing
}

// isAggregateAttestationOk returns true if the aggregate attestation is not nil (which can happen if the subscription wasn't successful).
func isAggregateAttestationOk(resp *eth2api.Response[*eth2p0.Attestation]) bool {
	return resp.Data != nil
}
