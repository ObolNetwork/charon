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
	"encoding/json"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
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

func TestGetCommitteeLength(t *testing.T) {
	var (
		commIdx = 123
		commLen = 140
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res := getCommitteesResponse{
			Data: []struct {
				Index      int   `json:"index"`
				Validators []int `json:"validators"`
			}([]struct {
				Index      int
				Validators []int
			}{
				{
					Index:      commIdx,
					Validators: rand.Perm(commLen),
				},
			}),
		}

		b, _ := json.Marshal(res)
		_, _ = w.Write(b)
	}))
	defer server.Close()

	tests := []struct {
		name       string
		beaconNode string
		commIdx    phase0.CommitteeIndex
		slot       phase0.Slot
		want       int
		wantErr    bool
	}{
		{
			name:       "happy path",
			beaconNode: server.URL,
			commIdx:    phase0.CommitteeIndex(commIdx),
			slot:       2,
			want:       commLen,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getCommitteeLength(context.Background(), tt.beaconNode, tt.commIdx, tt.slot)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
