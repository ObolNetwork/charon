// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fetcher_test

import (
	"context"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/beaconmock"
	"github.com/obolnetwork/charon/fetcher"
	"github.com/obolnetwork/charon/types"
)

func TestFetchAttester(t *testing.T) {
	ctx := context.Background()

	const (
		slot    = 1
		vIdxA   = 2
		vIdxB   = 3
		notZero = 99 // Validation require non-zero values
	)
	dutyArgA, err := types.EncodeAttesterDutyArg(&eth2v1.AttesterDuty{
		Slot:             slot,
		ValidatorIndex:   vIdxA,
		CommitteeIndex:   vIdxA,
		CommitteeLength:  notZero,
		CommitteesAtSlot: notZero,
	})
	require.NoError(t, err)

	dutyArgB, err := types.EncodeAttesterDutyArg(&eth2v1.AttesterDuty{
		Slot:             slot,
		ValidatorIndex:   vIdxB,
		CommitteeIndex:   vIdxB,
		CommitteeLength:  notZero,
		CommitteesAtSlot: notZero,
	})
	require.NoError(t, err)

	argSet := types.DutyArgSet{
		vIdxA: dutyArgA,
		vIdxB: dutyArgB,
	}
	duty := types.Duty{Type: types.DutyAttester, Slot: slot}

	fetch, err := fetcher.New(beaconmock.New())
	require.NoError(t, err)

	fetch.Subscribe(func(ctx context.Context, resDuty types.Duty, resDataSet types.DutyDataSet) error {
		require.Equal(t, duty, resDuty)
		require.Len(t, resDataSet, 2)

		dataA := resDataSet[types.VIdx(vIdxA)]
		dutyDataA, err := types.DecodeAttesterDutyData(dataA)
		require.NoError(t, err)
		require.EqualValues(t, slot, dutyDataA.Slot)
		require.EqualValues(t, vIdxA, dutyDataA.Index)

		dataB := resDataSet[types.VIdx(vIdxB)]
		dutyDataB, err := types.DecodeAttesterDutyData(dataB)
		require.NoError(t, err)
		require.EqualValues(t, slot, dutyDataB.Slot)
		require.EqualValues(t, vIdxB, dutyDataB.Index)

		return nil
	})

	err = fetch.Fetch(ctx, duty, argSet)
	require.NoError(t, err)
}
