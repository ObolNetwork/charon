// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package bcast_test

import (
	"context"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/api/v1/capella"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/bcast"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

type test struct {
	name     string          // Name of the test
	aggData  core.SignedData // Aggregated signed duty data object that needs to be broadcasted
	duty     core.DutyType   // Duty type
	bcastCnt int             // The no of times Broadcast() needs to be called
	asserted chan struct{}   // Closed when test output asserted
}

func TestBroadcast(t *testing.T) {
	testFuncs := []func(*testing.T, *beaconmock.Mock) test{
		attData,                   // Attestation
		proposalData,              // BeaconBlock
		blindedProposalData,       // BlindedBlock
		validatorRegistrationData, // ValidatorRegistration
		validatorExitData,         // ValidatorExit
		aggregateAttestationData,  // AggregateAttestation
		beaconCommitteeSelections, // BeaconCommitteeSelections
		syncCommitteeMessage,      // SyncCommitteeMessage
		syncCommitteeContribution, // SyncCommitteeContribution
	}

	for _, testFunc := range testFuncs {
		mock, err := beaconmock.New()
		require.NoError(t, err)

		test := testFunc(t, &mock)
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			bcaster, err := bcast.New(ctx, mock)
			require.NoError(t, err)

			for i := 0; i < test.bcastCnt; i++ {
				err := bcaster.Broadcast(ctx,
					core.Duty{Type: test.duty}, core.SignedDataSet{
						testutil.RandomCorePubKey(t): test.aggData,
					},
				)
				require.NoError(t, err)
			}

			require.NotNil(t, test.asserted)
			select {
			case <-test.asserted:
			default:
				require.Fail(t, "Asserted channel not closed")
			}
		})
	}
}

func attData(t *testing.T, mock *beaconmock.Mock) test {
	t.Helper()

	aggData := core.Attestation{Attestation: *testutil.RandomAttestation()}
	asserted := make(chan struct{})

	var submitted int
	mock.SubmitAttestationsFunc = func(ctx context.Context, attestations []*eth2p0.Attestation) error {
		require.Len(t, attestations, 1)
		require.Equal(t, aggData.Attestation, *attestations[0])

		submitted++
		if submitted == 1 {
			return nil
		}

		close(asserted)
		// Non-idempotent error returned by lighthouse but swallowed by bcast.
		return errors.New("Verification: PriorAttestationKnown")
	}

	return test{
		name:     "Broadcast Attestation",
		aggData:  aggData,
		duty:     core.DutyAttester,
		bcastCnt: 2,
		asserted: asserted,
	}
}

func proposalData(t *testing.T, mock *beaconmock.Mock) test {
	t.Helper()

	asserted := make(chan struct{})

	proposal1 := eth2api.VersionedSignedProposal{
		Version: eth2spec.DataVersionPhase0,
		Phase0: &eth2p0.SignedBeaconBlock{
			Message:   testutil.RandomPhase0BeaconBlock(),
			Signature: testutil.RandomEth2Signature(),
		},
	}

	aggData := core.VersionedSignedProposal{VersionedSignedProposal: proposal1}

	mock.SubmitProposalFunc = func(ctx context.Context, opts *eth2api.SubmitProposalOpts) error {
		require.Equal(t, proposal1, *opts.Proposal)
		close(asserted)

		return nil
	}

	return test{
		name:     "Broadcast Beacon Block Proposal",
		aggData:  aggData,
		duty:     core.DutyProposer,
		bcastCnt: 1,
		asserted: asserted,
	}
}

func blindedProposalData(t *testing.T, mock *beaconmock.Mock) test {
	t.Helper()

	asserted := make(chan struct{})

	proposal1 := eth2api.VersionedSignedProposal{
		Version: eth2spec.DataVersionPhase0,
		CapellaBlinded: &capella.SignedBlindedBeaconBlock{
			Message:   testutil.RandomCapellaBlindedBeaconBlock(),
			Signature: testutil.RandomEth2Signature(),
		},
	}

	aggData := core.VersionedSignedProposal{VersionedSignedProposal: proposal1}

	mock.SubmitProposalFunc = func(ctx context.Context, opts *eth2api.SubmitProposalOpts) error {
		require.Equal(t, proposal1, *opts.Proposal)
		close(asserted)

		return nil
	}

	return test{
		name:     "Broadcast Blinded Block Proposal",
		aggData:  aggData,
		duty:     core.DutyProposer,
		bcastCnt: 1,
		asserted: asserted,
	}
}

func validatorRegistrationData(t *testing.T, mock *beaconmock.Mock) test {
	t.Helper()

	asserted := make(chan struct{})
	registration := testutil.RandomCoreVersionedSignedValidatorRegistration(t).VersionedSignedValidatorRegistration
	aggData := core.VersionedSignedValidatorRegistration{VersionedSignedValidatorRegistration: registration}

	mock.SubmitValidatorRegistrationsFunc = func(ctx context.Context, registrations []*eth2api.VersionedSignedValidatorRegistration) error {
		require.Equal(t, aggData.VersionedSignedValidatorRegistration, *registrations[0])
		close(asserted)

		return nil
	}

	return test{
		name:     "Broadcast Validator Registration",
		aggData:  aggData,
		duty:     core.DutyBuilderRegistration,
		bcastCnt: 1,
		asserted: asserted,
	}
}

func validatorExitData(t *testing.T, mock *beaconmock.Mock) test {
	t.Helper()

	asserted := make(chan struct{})

	aggData := core.SignedVoluntaryExit{SignedVoluntaryExit: *testutil.RandomExit()}

	mock.SubmitVoluntaryExitFunc = func(ctx context.Context, exit2 *eth2p0.SignedVoluntaryExit) error {
		require.Equal(t, aggData.SignedVoluntaryExit, *exit2)
		close(asserted)

		return nil
	}

	return test{
		name:     "Broadcast Validator Exit",
		aggData:  aggData,
		duty:     core.DutyExit,
		bcastCnt: 1,
		asserted: asserted,
	}
}

func aggregateAttestationData(t *testing.T, mock *beaconmock.Mock) test {
	t.Helper()

	asserted := make(chan struct{})
	aggAndProof := testutil.RandomSignedAggregateAndProof()
	aggData := core.SignedAggregateAndProof{SignedAggregateAndProof: *aggAndProof}

	mock.SubmitAggregateAttestationsFunc = func(ctx context.Context, aggregateAndProofs []*eth2p0.SignedAggregateAndProof) error {
		require.Equal(t, aggAndProof, aggregateAndProofs[0])
		close(asserted)

		return nil
	}

	return test{
		name:     "Broadcast Aggregate Attestation",
		aggData:  aggData,
		duty:     core.DutyAggregator,
		bcastCnt: 1,
		asserted: asserted,
	}
}

func beaconCommitteeSelections(t *testing.T, _ *beaconmock.Mock) test {
	t.Helper()

	asserted := make(chan struct{})
	close(asserted)

	return test{
		name:     "Broadcast Beacon Committee Selections",
		aggData:  testutil.RandomCoreBeaconCommitteeSelection(),
		duty:     core.DutyPrepareAggregator,
		bcastCnt: 0,
		asserted: asserted,
	}
}

func syncCommitteeMessage(t *testing.T, mock *beaconmock.Mock) test {
	t.Helper()

	asserted := make(chan struct{})
	msg := core.NewSignedSyncMessage(testutil.RandomSyncCommitteeMessage())
	mock.SubmitSyncCommitteeMessagesFunc = func(ctx context.Context, messages []*altair.SyncCommitteeMessage) error {
		require.Equal(t, msg.SyncCommitteeMessage, *messages[0])
		close(asserted)

		return nil
	}

	return test{
		name:     "Broadcast Sync Committee Message",
		aggData:  msg,
		duty:     core.DutySyncMessage,
		bcastCnt: 1,
		asserted: asserted,
	}
}

func syncCommitteeContribution(t *testing.T, mock *beaconmock.Mock) test {
	t.Helper()

	asserted := make(chan struct{})
	contribution := core.NewSignedSyncContributionAndProof(testutil.RandomSignedSyncContributionAndProof())
	mock.SubmitSyncCommitteeContributionsFunc = func(ctx context.Context, contributionAndProofs []*altair.SignedContributionAndProof) error {
		require.Equal(t, contribution.SignedContributionAndProof, *contributionAndProofs[0])
		close(asserted)

		return nil
	}

	return test{
		name:     "Broadcast Sync Committee Contribution",
		aggData:  contribution,
		duty:     core.DutySyncContribution,
		bcastCnt: 1,
		asserted: asserted,
	}
}
