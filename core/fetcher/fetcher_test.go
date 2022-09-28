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

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/fetcher"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
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

	dutyB := eth2v1.AttesterDuty{
		Slot:             slot,
		ValidatorIndex:   vIdxB,
		CommitteeIndex:   vIdxB,
		CommitteeLength:  notZero,
		CommitteesAtSlot: notZero,
	}

	defSet := core.DutyDefinitionSet{
		pubkeysByIdx[vIdxA]: core.NewAttesterDefinition(&dutyA),
		pubkeysByIdx[vIdxB]: core.NewAttesterDefinition(&dutyB),
	}
	duty := core.NewAttesterDuty(slot)
	bmock, err := beaconmock.New()
	require.NoError(t, err)
	fetch, err := fetcher.New(bmock)
	require.NoError(t, err)

	fetch.Subscribe(func(ctx context.Context, resDuty core.Duty, resDataSet core.UnsignedDataSet) error {
		require.Equal(t, duty, resDuty)
		require.Len(t, resDataSet, 2)

		dutyDataA := resDataSet[pubkeysByIdx[vIdxA]].(core.AttestationData)
		require.EqualValues(t, slot, dutyDataA.Data.Slot)
		require.EqualValues(t, vIdxA, dutyDataA.Data.Index)
		require.EqualValues(t, dutyA, dutyDataA.Duty)

		dutyDataB := resDataSet[pubkeysByIdx[vIdxB]].(core.AttestationData)
		require.EqualValues(t, slot, dutyDataB.Data.Slot)
		require.EqualValues(t, vIdxB, dutyDataB.Data.Index)
		require.EqualValues(t, dutyB, dutyDataB.Duty)

		return nil
	})

	err = fetch.Fetch(ctx, duty, defSet)
	require.NoError(t, err)
}

func TestFetchAggregator(t *testing.T) {
	ctx := context.Background()

	const (
		slot  = 1
		vIdxA = 2
		vIdxB = 3
	)

	commLen := 0 // commLen of 0, results in eth2exp.IsAttestationAggregator to always return IsAggregator=true
	nilAggregate := false

	duty := core.NewAggregatorDuty(slot)

	pubkeysByIdx := map[eth2p0.ValidatorIndex]core.PubKey{
		vIdxA: testutil.RandomCorePubKey(t),
		vIdxB: testutil.RandomCorePubKey(t),
	}

	defSet := core.DutyDefinitionSet{
		pubkeysByIdx[vIdxA]: core.NewEmptyDefinition(),
		pubkeysByIdx[vIdxB]: core.NewEmptyDefinition(),
	}

	attA := testutil.RandomAttestation()
	attB := testutil.RandomAttestation()
	attByCommIdx := map[int64]*eth2p0.Attestation{
		int64(attA.Data.Index): attA,
		int64(attB.Data.Index): attB,
	}
	signedCommSubByPubKey := map[core.PubKey]core.SignedData{
		pubkeysByIdx[vIdxA]: testutil.RandomSignedBeaconCommitteeSubscription(vIdxA, slot, int(attA.Data.Index)),
		pubkeysByIdx[vIdxB]: testutil.RandomSignedBeaconCommitteeSubscription(vIdxB, slot, int(attB.Data.Index)),
	}

	bmock, err := beaconmock.New()
	require.NoError(t, err)

	bmock.BeaconCommitteesAtEpochFunc = func(_ context.Context, _ string, _ eth2p0.Epoch) ([]*eth2v1.BeaconCommittee, error) {
		return []*eth2v1.BeaconCommittee{
			beaconCommittee(attA.Data.Index, commLen),
			beaconCommittee(attB.Data.Index, commLen),
		}, nil
	}

	bmock.AggregateAttestationFunc = func(ctx context.Context, slot eth2p0.Slot, root eth2p0.Root) (*eth2p0.Attestation, error) {
		if nilAggregate {
			return nil, nil //nolint:nilnil // This reproduces what go-eth2-client does
		}
		for _, att := range attByCommIdx {
			dataRoot, err := att.Data.HashTreeRoot()
			require.NoError(t, err)
			if dataRoot == root {
				return att, nil
			}
		}

		return nil, errors.New("expected unknown root")
	}

	fetch, err := fetcher.New(bmock)
	require.NoError(t, err)

	fetch.RegisterAggSigDB(func(ctx context.Context, duty core.Duty, key core.PubKey) (core.SignedData, error) {
		require.Equal(t, core.NewPrepareAggregatorDuty(slot), duty)

		return signedCommSubByPubKey[key], nil
	})

	fetch.RegisterAwaitAttData(func(ctx context.Context, slot int64, commIdx int64) (*eth2p0.AttestationData, error) {
		return attByCommIdx[commIdx].Data, nil
	})

	done := errors.New("done")
	fetch.Subscribe(func(ctx context.Context, resDuty core.Duty, resDataSet core.UnsignedDataSet) error {
		require.Equal(t, duty, resDuty)
		require.Len(t, resDataSet, 2)

		for _, aggAtt := range resDataSet {
			aggregated, ok := aggAtt.(core.AggregatedAttestation)
			require.True(t, ok)

			att, ok := attByCommIdx[int64(aggregated.Attestation.Data.Index)]
			require.True(t, ok)
			require.Equal(t, aggregated.Attestation, *att)
		}

		return done
	})

	err = fetch.Fetch(ctx, duty, defSet)
	require.ErrorIs(t, err, done)

	// Test no aggregators for slot
	// First find a committee length that results in eth2exp.IsAttestationAggregator to return IsAggregator=false
	var foundNoAggLen bool
	for commLen = 1000; commLen < 1200; commLen++ {
		var isAnyAgg bool
		for _, vIdx := range []int{vIdxA, vIdxB} {
			sub := signedCommSubByPubKey[pubkeysByIdx[eth2p0.ValidatorIndex(vIdx)]].(core.SignedBeaconCommitteeSubscription)
			isAgg, err := eth2exp.IsAttestationAggregator(ctx, bmock, sub.Slot, sub.CommitteeIndex, sub.SelectionProof)
			require.NoError(t, err)

			if isAgg {
				isAnyAgg = true
				break
			}
		}

		if !isAnyAgg {
			foundNoAggLen = true
			break
		}
	}
	require.True(t, foundNoAggLen)

	err = fetch.Fetch(ctx, duty, defSet)
	require.NoError(t, err)

	// Test nil, nil AggregateAttestation response.
	commLen = 0
	nilAggregate = true

	err = fetch.Fetch(ctx, duty, defSet)
	require.ErrorContains(t, err, "aggregate attestation not found by root (retryable)")
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
	dutyB := eth2v1.ProposerDuty{
		Slot:           slot,
		ValidatorIndex: vIdxB,
	}
	defSet := core.DutyDefinitionSet{
		pubkeysByIdx[vIdxA]: core.NewProposerDefinition(&dutyA),
		pubkeysByIdx[vIdxB]: core.NewProposerDefinition(&dutyB),
	}
	duty := core.NewProposerDuty(slot)

	randaoA := testutil.RandomCoreSignature()
	randaoB := testutil.RandomCoreSignature()
	randaoByPubKey := map[core.PubKey]core.SignedData{
		pubkeysByIdx[vIdxA]: randaoA,
		pubkeysByIdx[vIdxB]: randaoB,
	}

	bmock, err := beaconmock.New()
	require.NoError(t, err)
	fetch, err := fetcher.New(bmock)
	require.NoError(t, err)

	fetch.RegisterAggSigDB(func(ctx context.Context, duty core.Duty, key core.PubKey) (core.SignedData, error) {
		return randaoByPubKey[key], nil
	})

	fetch.Subscribe(func(ctx context.Context, resDuty core.Duty, resDataSet core.UnsignedDataSet) error {
		require.Equal(t, duty, resDuty)
		require.Len(t, resDataSet, 2)

		dutyDataA := resDataSet[pubkeysByIdx[vIdxA]].(core.VersionedBeaconBlock)
		slotA, err := dutyDataA.Slot()
		require.NoError(t, err)
		require.EqualValues(t, slot, slotA)
		assertRandao(t, randaoByPubKey[pubkeysByIdx[vIdxA]].Signature().ToETH2(), dutyDataA)

		dutyDataB := resDataSet[pubkeysByIdx[vIdxB]].(core.VersionedBeaconBlock)
		slotB, err := dutyDataB.Slot()
		require.NoError(t, err)
		require.EqualValues(t, slot, slotB)
		assertRandao(t, randaoByPubKey[pubkeysByIdx[vIdxB]].Signature().ToETH2(), dutyDataB)

		return nil
	})

	err = fetch.Fetch(ctx, duty, defSet)
	require.NoError(t, err)
}

func TestFetchBuilderProposer(t *testing.T) {
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
	dutyB := eth2v1.ProposerDuty{
		Slot:           slot,
		ValidatorIndex: vIdxB,
	}
	defSet := core.DutyDefinitionSet{
		pubkeysByIdx[vIdxA]: core.NewProposerDefinition(&dutyA),
		pubkeysByIdx[vIdxB]: core.NewProposerDefinition(&dutyB),
	}
	duty := core.NewBuilderProposerDuty(slot)

	randaoA := testutil.RandomCoreSignature()
	randaoB := testutil.RandomCoreSignature()
	randaoByPubKey := map[core.PubKey]core.SignedData{
		pubkeysByIdx[vIdxA]: randaoA,
		pubkeysByIdx[vIdxB]: randaoB,
	}

	bmock, err := beaconmock.New()
	require.NoError(t, err)
	fetch, err := fetcher.New(bmock)
	require.NoError(t, err)

	fetch.RegisterAggSigDB(func(ctx context.Context, duty core.Duty, key core.PubKey) (core.SignedData, error) {
		return randaoByPubKey[key], nil
	})

	fetch.Subscribe(func(ctx context.Context, resDuty core.Duty, resDataSet core.UnsignedDataSet) error {
		require.Equal(t, duty, resDuty)
		require.Len(t, resDataSet, 2)

		dutyDataA := resDataSet[pubkeysByIdx[vIdxA]].(core.VersionedBlindedBeaconBlock)
		slotA, err := dutyDataA.Slot()
		require.NoError(t, err)
		require.EqualValues(t, slot, slotA)
		assertRandaoBlindedBlock(t, randaoByPubKey[pubkeysByIdx[vIdxA]].Signature().ToETH2(), dutyDataA)

		dutyDataB := resDataSet[pubkeysByIdx[vIdxB]].(core.VersionedBlindedBeaconBlock)
		slotB, err := dutyDataB.Slot()
		require.NoError(t, err)
		require.EqualValues(t, slot, slotB)
		assertRandaoBlindedBlock(t, randaoByPubKey[pubkeysByIdx[vIdxB]].Signature().ToETH2(), dutyDataB)

		return nil
	})

	err = fetch.Fetch(ctx, duty, defSet)
	require.NoError(t, err)
}

func assertRandao(t *testing.T, randao eth2p0.BLSSignature, block core.VersionedBeaconBlock) {
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

func assertRandaoBlindedBlock(t *testing.T, randao eth2p0.BLSSignature, block core.VersionedBlindedBeaconBlock) {
	t.Helper()

	switch block.Version {
	case spec.DataVersionBellatrix:
		require.EqualValues(t, randao, block.Bellatrix.Body.RANDAOReveal)
	default:
		require.Fail(t, "invalid block")
	}
}

// beaconCommittee returns a BeaconCommittee with the given committee index and a list of commLen validator indexes.
func beaconCommittee(commIdx eth2p0.CommitteeIndex, commLen int) *eth2v1.BeaconCommittee {
	var (
		slot = eth2p0.Slot(1)
		vals []eth2p0.ValidatorIndex
	)
	for idx := 1; idx <= commLen; idx++ {
		vals = append(vals, eth2p0.ValidatorIndex(idx))
	}

	return &eth2v1.BeaconCommittee{
		Slot:       slot,
		Index:      commIdx,
		Validators: vals,
	}
}
