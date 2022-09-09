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

package eth2exp

import (
	"context"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
)

// IsAggregator exports the unexported function isAggregator to package eth2exp_test.
func IsAggregator(ctx context.Context, eth2Cl eth2Provider, commLen uint64, slotSig eth2p0.BLSSignature) (bool, error) {
	return isAggregator(ctx, eth2Cl, commLen, slotSig)
}
