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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCalculateCommitteeSubscriptionResponse(t *testing.T) {
	tests := []struct {
		name         string
		beaconNode   string
		subscription BeaconCommitteeSubscription
		want         BeaconCommitteeSubscriptionResponse
		wantErr      bool
	}{
		{
			name:         "valid",
			beaconNode:   "http://localhost:5699/",
			subscription: BeaconCommitteeSubscription{},
			want:         BeaconCommitteeSubscriptionResponse{},
			wantErr:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CalculateCommitteeSubscriptionResponse(context.Background(), tt.beaconNode, tt.subscription)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
