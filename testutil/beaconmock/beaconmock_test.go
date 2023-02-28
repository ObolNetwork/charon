// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package beaconmock_test

import (
	"context"
	"testing"

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

	attDuty, err := bmock.AttesterDuties(context.Background(), 1, []eth2p0.ValidatorIndex{2})
	require.NoError(t, err)
	testutil.RequireGoldenJSON(t, attDuty)
}

func TestDeterministicProposerDuties(t *testing.T) {
	bmock, err := beaconmock.New(
		beaconmock.WithValidatorSet(beaconmock.ValidatorSetA),
		beaconmock.WithDeterministicProposerDuties(1),
	)
	require.NoError(t, err)

	proDuty, err := bmock.ProposerDuties(context.Background(), 1, []eth2p0.ValidatorIndex{2})
	require.NoError(t, err)
	testutil.RequireGoldenJSON(t, proDuty)
}

func TestAttestationStore(t *testing.T) {
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	ctx := context.Background()

	attData, err := bmock.AttestationData(ctx, 1, 2)
	require.NoError(t, err)
	testutil.RequireGoldenJSON(t, attData)

	root, err := attData.HashTreeRoot()
	require.NoError(t, err)

	att, err := bmock.AggregateAttestation(ctx, 0, root) // Slot is ignored.
	require.NoError(t, err)
	require.Equal(t, attData, att.Data)

	_, err = bmock.AggregateAttestation(ctx, attData.Slot, eth2p0.Root{}) // Not found
	require.Error(t, err)

	// New attestation data with much larger slots delete old ones.
	_, err = bmock.AttestationData(ctx, 99, 2)
	require.NoError(t, err)

	_, err = bmock.AggregateAttestation(ctx, 0, root) // Deleted.
	require.Error(t, err)
}
