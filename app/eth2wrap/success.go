// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package eth2wrap

import (
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// isSyncStateOk returns tue if the sync state is not syncing.
func isSyncStateOk(s *apiv1.SyncState) bool {
	return !s.IsSyncing
}

// isAggregateAttestationOk returns tue if the aggregate attestation is not nil (which can happen if the subscription wasn't done).
func isAggregateAttestationOk(att *phase0.Attestation) bool {
	return att != nil
}
