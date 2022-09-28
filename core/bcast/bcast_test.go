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

package bcast_test

import (
	"context"
	mrand "math/rand"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/bcast"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestBroadcastAttestation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mock, err := beaconmock.New()
	require.NoError(t, err)

	aggData := core.Attestation{Attestation: *testutil.RandomAttestation()}

	// Assert output and return lighthouse known error on duplicates
	var submitted int
	mock.SubmitAttestationsFunc = func(ctx context.Context, attestations []*eth2p0.Attestation) error {
		require.Len(t, attestations, 1)
		require.Equal(t, aggData.Attestation, *attestations[0])

		submitted++
		if submitted > 1 {
			// Non-idempotent error returned by lighthouse but swallowed by bcast.
			return errors.New("Verification: PriorAttestationKnown")
		}

		return nil
	}

	bcaster, err := bcast.New(ctx, mock)
	require.NoError(t, err)

	err = bcaster.Broadcast(ctx, core.Duty{Type: core.DutyAttester}, "", aggData)
	require.NoError(t, err)
	err = bcaster.Broadcast(ctx, core.Duty{Type: core.DutyAttester}, "", aggData)
	require.NoError(t, err)
}

func TestBroadcastBeaconBlock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	mock, err := beaconmock.New()
	require.NoError(t, err)

	block1 := spec.VersionedSignedBeaconBlock{
		Version: spec.DataVersionPhase0,
		Phase0: &eth2p0.SignedBeaconBlock{
			Message:   testutil.RandomPhase0BeaconBlock(),
			Signature: testutil.RandomEth2Signature(),
		},
	}

	aggData := core.VersionedSignedBeaconBlock{VersionedSignedBeaconBlock: block1}

	mock.SubmitBeaconBlockFunc = func(ctx context.Context, block2 *spec.VersionedSignedBeaconBlock) error {
		require.Equal(t, block1, *block2)
		cancel()

		return ctx.Err()
	}

	bcaster, err := bcast.New(ctx, mock)
	require.NoError(t, err)

	err = bcaster.Broadcast(ctx, core.Duty{Type: core.DutyProposer}, "", aggData)
	require.ErrorIs(t, err, context.Canceled)

	<-ctx.Done()
}

func TestBroadcastBlindedBeaconBlock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	mock, err := beaconmock.New()
	require.NoError(t, err)

	block1 := eth2api.VersionedSignedBlindedBeaconBlock{
		Version: spec.DataVersionBellatrix,
		Bellatrix: &eth2v1.SignedBlindedBeaconBlock{
			Message:   testutil.RandomBellatrixBlindedBeaconBlock(t),
			Signature: testutil.RandomEth2Signature(),
		},
	}

	aggData := core.VersionedSignedBlindedBeaconBlock{VersionedSignedBlindedBeaconBlock: block1}

	mock.SubmitBlindedBeaconBlockFunc = func(ctx context.Context, block2 *eth2api.VersionedSignedBlindedBeaconBlock) error {
		require.Equal(t, block1, *block2)
		cancel()

		return ctx.Err()
	}

	bcaster, err := bcast.New(ctx, mock)
	require.NoError(t, err)

	err = bcaster.Broadcast(ctx, core.Duty{Type: core.DutyBuilderProposer}, "", aggData)
	require.ErrorIs(t, err, context.Canceled)

	<-ctx.Done()
}

func TestValidatorRegistration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	mock, err := beaconmock.New()
	require.NoError(t, err)

	registration := testutil.RandomCoreVersionedSignedValidatorRegistration(t).VersionedSignedValidatorRegistration

	aggData := core.VersionedSignedValidatorRegistration{VersionedSignedValidatorRegistration: registration}

	mock.SubmitValidatorRegistrationsFunc = func(ctx context.Context, registrations []*eth2api.VersionedSignedValidatorRegistration) error {
		require.Equal(t, aggData.VersionedSignedValidatorRegistration, *registrations[0])
		cancel()

		return ctx.Err()
	}

	bcaster, err := bcast.New(ctx, mock)
	require.NoError(t, err)

	err = bcaster.Broadcast(ctx, core.Duty{Type: core.DutyBuilderRegistration}, "", aggData)
	require.ErrorIs(t, err, context.Canceled)

	<-ctx.Done()
}

func TestBroadcastExit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	mock, err := beaconmock.New()
	require.NoError(t, err)

	aggData := core.SignedVoluntaryExit{SignedVoluntaryExit: *testutil.RandomExit()}

	mock.SubmitVoluntaryExitFunc = func(ctx context.Context, exit2 *eth2p0.SignedVoluntaryExit) error {
		require.Equal(t, aggData.SignedVoluntaryExit, *exit2)
		cancel()

		return ctx.Err()
	}

	bcaster, err := bcast.New(ctx, mock)
	require.NoError(t, err)

	err = bcaster.Broadcast(ctx, core.Duty{Type: core.DutyExit}, "", aggData)
	require.ErrorIs(t, err, context.Canceled)

	<-ctx.Done()
}

func TestBroadcastBeaconCommitteeSubscriptionV2(t *testing.T) {
	ctx := context.Background()
	mock, err := beaconmock.New()
	require.NoError(t, err)

	subscription := testutil.RandomBeaconCommitteeSubscription()
	subscription.IsAggregator = true // We use committee length=0 below, so the result will be IsAggregator=true.

	aggData := core.SignedBeaconCommitteeSubscription{BeaconCommitteeSubscription: *subscription}

	mock.BeaconCommitteesAtEpochFunc = func(context.Context, string, eth2p0.Epoch) ([]*eth2v1.BeaconCommittee, error) {
		return []*eth2v1.BeaconCommittee{{Index: subscription.CommitteeIndex}}, nil
	}
	done := make(chan struct{})
	mock.SubmitBeaconCommitteeSubscriptionsV2Func = func(ctx context.Context, subs []*eth2exp.BeaconCommitteeSubscription) ([]*eth2exp.BeaconCommitteeSubscription, error) {
		require.Equal(t, aggData.BeaconCommitteeSubscription, *subs[0])
		close(done)

		return subs, nil
	}

	bcaster, err := bcast.New(ctx, mock)
	require.NoError(t, err)

	err = bcaster.Broadcast(ctx, core.Duty{Type: core.DutyPrepareAggregator}, "", aggData)
	require.NoError(t, err)

	<-done
}

func TestBroadcastBeaconCommitteeSubscriptionV1(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	const (
		slot    = 1
		vIdx    = 1
		commIdx = 1
		commLen = 43
	)

	mock, err := beaconmock.New(beaconmock.WithValidatorSet(beaconmock.ValidatorSetA))
	require.NoError(t, err)

	_, secret, err := tbls.KeygenWithSeed(mrand.New(mrand.NewSource(1)))
	require.NoError(t, err)

	sigRoot, err := eth2util.SlotHashRoot(slot)
	require.NoError(t, err)

	slotsPerEpoch, err := mock.SlotsPerEpoch(ctx)
	require.NoError(t, err)

	sigData, err := signing.GetDataRoot(ctx, mock, signing.DomainSelectionProof, eth2p0.Epoch(uint64(1)/slotsPerEpoch), sigRoot)
	require.NoError(t, err)

	sig, _ := tbls.Sign(secret, sigData[:])
	blssig := tblsconv.SigToETH2(sig)

	mock.BeaconCommitteesAtEpochFunc = func(_ context.Context, stateID string, epoch eth2p0.Epoch) ([]*eth2v1.BeaconCommittee, error) {
		require.Equal(t, "head", stateID)
		require.Equal(t, eth2p0.Epoch(uint64(slot)/slotsPerEpoch), epoch)

		var vals []eth2p0.ValidatorIndex
		for idx := 1; idx <= commLen; idx++ {
			vals = append(vals, eth2p0.ValidatorIndex(idx))
		}

		return []*eth2v1.BeaconCommittee{
			{
				Slot:       slot,
				Index:      commIdx,
				Validators: vals,
			},
		}, nil
	}

	subscription := eth2exp.BeaconCommitteeSubscription{
		ValidatorIndex: vIdx,
		Slot:           slot,
		CommitteeIndex: commIdx,
		SelectionProof: blssig,
		IsAggregator:   true,
	}
	aggData := core.SignedBeaconCommitteeSubscription{BeaconCommitteeSubscription: subscription}

	mock.SubmitBeaconCommitteeSubscriptionsV2Func = func(ctx context.Context, subscriptions []*eth2exp.BeaconCommitteeSubscription) ([]*eth2exp.BeaconCommitteeSubscription, error) {
		require.Equal(t, aggData.BeaconCommitteeSubscription, *subscriptions[0])

		return nil, errors.New("404 not found")
	}
	mock.SubmitBeaconCommitteeSubscriptionsFunc = func(ctx context.Context, subscriptions []*eth2v1.BeaconCommitteeSubscription) error {
		require.Equal(t, eth2v1.BeaconCommitteeSubscription{
			ValidatorIndex: vIdx,
			Slot:           slot,
			CommitteeIndex: commIdx,
			IsAggregator:   true,
		}, *subscriptions[0])
		cancel()

		return ctx.Err()
	}

	bcaster, err := bcast.New(ctx, mock)
	require.NoError(t, err)

	err = bcaster.Broadcast(ctx, core.Duty{Type: core.DutyPrepareAggregator}, "", aggData)
	require.ErrorIs(t, err, context.Canceled)

	<-ctx.Done()
}

func TestBroadcastAggregateAttestation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	mock, err := beaconmock.New()
	require.NoError(t, err)

	aggAndProof := testutil.RandomSignedAggregateAndProof()
	data := core.SignedAggregateAndProof{SignedAggregateAndProof: *aggAndProof}

	mock.SubmitAggregateAttestationsFunc = func(ctx context.Context, aggregateAndProofs []*eth2p0.SignedAggregateAndProof) error {
		require.Equal(t, aggAndProof, aggregateAndProofs[0])
		cancel()

		return ctx.Err()
	}

	bcaster, err := bcast.New(ctx, mock)
	require.NoError(t, err)

	err = bcaster.Broadcast(ctx, core.Duty{Type: core.DutyAggregator}, "", data)
	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled)

	<-ctx.Done()
}
