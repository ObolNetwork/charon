// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package beaconmock_test

import (
	"context"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

//go:generate go test . -update

func TestDeterministicAttesterDuties(t *testing.T) {
	bmock, err := beaconmock.New(
		beaconmock.WithValidatorSet(beaconmock.ValidatorSetA),
		beaconmock.WithDeterministicAttesterDuties(1),
	)
	require.NoError(t, err)

	opts := &eth2api.AttesterDutiesOpts{
		Epoch:   1,
		Indices: []eth2p0.ValidatorIndex{2},
	}
	resp, err := bmock.AttesterDuties(context.Background(), opts)
	require.NoError(t, err)
	testutil.RequireGoldenJSON(t, resp.Data)
}

func TestDeterministicProposerDuties(t *testing.T) {
	bmock, err := beaconmock.New(
		beaconmock.WithValidatorSet(beaconmock.ValidatorSetA),
		beaconmock.WithDeterministicProposerDuties(1),
	)
	require.NoError(t, err)

	opts := &eth2api.ProposerDutiesOpts{
		Epoch:   1,
		Indices: []eth2p0.ValidatorIndex{2},
	}
	resp, err := bmock.ProposerDuties(context.Background(), opts)
	require.NoError(t, err)
	testutil.RequireGoldenJSON(t, resp.Data)
}

func TestAttestationStore(t *testing.T) {
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	ctx := context.Background()

	opts := &eth2api.AttestationDataOpts{
		Slot:           1,
		CommitteeIndex: 2,
	}
	resp, err := bmock.AttestationData(ctx, opts)
	require.NoError(t, err)
	attData := resp.Data
	testutil.RequireGoldenJSON(t, attData)

	root, err := attData.HashTreeRoot()
	require.NoError(t, err)

	aggAttOpts := &eth2api.AggregateAttestationOpts{
		Slot:                0,
		AttestationDataRoot: root,
	}
	bmockResp, err := bmock.AggregateAttestation(ctx, aggAttOpts) // Slot is ignored.
	require.NoError(t, err)
	att := bmockResp.Data
	require.Equal(t, attData, att.Data)

	aggAttopts2 := &eth2api.AggregateAttestationOpts{
		Slot:                attData.Slot,
		AttestationDataRoot: eth2p0.Root{},
	}
	_, err = bmock.AggregateAttestation(ctx, aggAttopts2) // Not found
	require.Error(t, err)

	// New attestation data with much larger slots delete old ones.
	attDataOpts := &eth2api.AttestationDataOpts{
		Slot:           99,
		CommitteeIndex: 2,
	}
	_, err = bmock.AttestationData(ctx, attDataOpts)
	require.NoError(t, err)

	aggDataOpts := &eth2api.AggregateAttestationOpts{
		Slot:                0,
		AttestationDataRoot: root,
	}
	_, err = bmock.AggregateAttestation(ctx, aggDataOpts) // Deleted.
	require.Error(t, err)
}
