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

package fetcher_test

import (
	"context"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/fetcher"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestFetchAttester(t *testing.T) {
	ctx := context.Background()

	const (
		slot    = 1
		vIdxA   = 2
		vIdxB   = 3
		notZero = 99 // Validation require non-zero values
	)

	pubkeysByIdx := map[eth2p0.ValidatorIndex]core.PubKey{
		vIdxA: testutil.RandomCorePubKey(t),
		vIdxB: testutil.RandomCorePubKey(t),
	}

	dutyA := eth2v1.AttesterDuty{
		Slot:             slot,
		ValidatorIndex:   vIdxA,
		CommitteeIndex:   vIdxA,
		CommitteeLength:  notZero,
		CommitteesAtSlot: notZero,
	}
	fetchArgA, err := core.EncodeAttesterDutyDefinition(&dutyA)
	require.NoError(t, err)

	dutyB := eth2v1.AttesterDuty{
		Slot:             slot,
		ValidatorIndex:   vIdxB,
		CommitteeIndex:   vIdxB,
		CommitteeLength:  notZero,
		CommitteesAtSlot: notZero,
	}
	fetchArgB, err := core.EncodeAttesterDutyDefinition(&dutyB)
	require.NoError(t, err)

	argSet := core.DutyDefinitionSet{
		pubkeysByIdx[vIdxA]: fetchArgA,
		pubkeysByIdx[vIdxB]: fetchArgB,
	}
	duty := core.Duty{Type: core.DutyAttester, Slot: slot}

	bmock, err := beaconmock.New()
	require.NoError(t, err)
	fetch, err := fetcher.New(bmock)
	require.NoError(t, err)

	fetch.Subscribe(func(ctx context.Context, resDuty core.Duty, resDataSet core.UnsignedDataSet) error {
		require.Equal(t, duty, resDuty)
		require.Len(t, resDataSet, 2)

		dataA := resDataSet[pubkeysByIdx[vIdxA]]
		dutyDataA, err := core.DecodeAttesterUnsignedData(dataA)
		require.NoError(t, err)
		require.EqualValues(t, slot, dutyDataA.Data.Slot)
		require.EqualValues(t, vIdxA, dutyDataA.Data.Index)
		require.EqualValues(t, dutyA, dutyDataA.Duty)

		dataB := resDataSet[pubkeysByIdx[vIdxB]]
		dutyDataB, err := core.DecodeAttesterUnsignedData(dataB)
		require.NoError(t, err)
		require.EqualValues(t, slot, dutyDataB.Data.Slot)
		require.EqualValues(t, vIdxB, dutyDataB.Data.Index)
		require.EqualValues(t, dutyB, dutyDataB.Duty)

		return nil
	})

	err = fetch.Fetch(ctx, duty, argSet)
	require.NoError(t, err)
}

func TestFetchProposer(t *testing.T) {
	ctx := context.Background()

	const (
		slot  = 1
		vIdxA = 2
		vIdxB = 3
	)

	pubkeysByIdx := map[eth2p0.ValidatorIndex]core.PubKey{
		vIdxA: testutil.RandomCorePubKey(t),
		vIdxB: testutil.RandomCorePubKey(t),
	}

	dutyA := eth2v1.ProposerDuty{
		Slot:           slot,
		ValidatorIndex: vIdxA,
	}
	fetchArgA, err := core.EncodeProposerDutyDefinition(&dutyA)
	require.NoError(t, err)

	dutyB := eth2v1.ProposerDuty{
		Slot:           slot,
		ValidatorIndex: vIdxB,
	}
	fetchArgB, err := core.EncodeProposerDutyDefinition(&dutyB)
	require.NoError(t, err)

	argSet := core.DutyDefinitionSet{
		pubkeysByIdx[vIdxA]: fetchArgA,
		pubkeysByIdx[vIdxB]: fetchArgB,
	}
	duty := core.Duty{Type: core.DutyProposer, Slot: slot}

	randaoA := core.GroupSignedData{
		Data:      nil,
		Signature: testutil.RandomCoreSignature(),
	}
	randaoB := core.GroupSignedData{
		Data:      nil,
		Signature: testutil.RandomCoreSignature(),
	}
	randaoByPubKey := map[core.PubKey]core.GroupSignedData{
		pubkeysByIdx[vIdxA]: randaoA,
		pubkeysByIdx[vIdxB]: randaoB,
	}

	bmock, err := beaconmock.New()
	require.NoError(t, err)
	fetch, err := fetcher.New(bmock)
	require.NoError(t, err)

	fetch.RegisterGroupSigDB(func(ctx context.Context, duty core.Duty, key core.PubKey) (core.GroupSignedData, error) {
		return randaoByPubKey[key], nil
	})

	fetch.Subscribe(func(ctx context.Context, resDuty core.Duty, resDataSet core.UnsignedDataSet) error {
		require.Equal(t, duty, resDuty)
		require.Len(t, resDataSet, 2)

		dataA := resDataSet[pubkeysByIdx[vIdxA]]
		dutyDataA, err := core.DecodeProposerUnsignedData(dataA)
		require.NoError(t, err)

		slotA, err := dutyDataA.Slot()
		require.NoError(t, err)
		require.EqualValues(t, slot, slotA)
		assertRandao(t, randaoByPubKey[pubkeysByIdx[vIdxA]].Signature.ToETH2(), dutyDataA)

		dataB := resDataSet[pubkeysByIdx[vIdxB]]
		dutyDataB, err := core.DecodeProposerUnsignedData(dataB)
		require.NoError(t, err)

		slotB, err := dutyDataB.Slot()
		require.NoError(t, err)
		require.EqualValues(t, slot, slotB)
		assertRandao(t, randaoByPubKey[pubkeysByIdx[vIdxB]].Signature.ToETH2(), dutyDataB)

		return nil
	})

	err = fetch.Fetch(ctx, duty, argSet)
	require.NoError(t, err)
}

func assertRandao(t *testing.T, randao eth2p0.BLSSignature, block *spec.VersionedBeaconBlock) {
	t.Helper()

	switch block.Version {
	case spec.DataVersionPhase0:
		require.EqualValues(t, randao, block.Phase0.Body.RANDAOReveal)
	case spec.DataVersionAltair:
		require.EqualValues(t, randao, block.Altair.Body.RANDAOReveal)
	case spec.DataVersionBellatrix:
		require.EqualValues(t, randao, block.Bellatrix.Body.RANDAOReveal)
	default:
		require.Fail(t, "invalid block")
	}
}
