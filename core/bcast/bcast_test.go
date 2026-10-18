// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package bcast_test

import (
	"context"
	"net/http"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
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
		validatorExitData,         // ValidatorExit
		aggregateAttestationData,  // AggregateAttestation
		beaconCommitteeSelections, // BeaconCommitteeSelections
		syncCommitteeMessage,      // SyncCommitteeMessage
		syncCommitteeContribution, // SyncCommitteeContribution
		payloadAttestationMessage, // PayloadAttestationMessage
		proposerPreferences,       // ProposerPreferences
		executionPayloadEnvelope,  // ExecutionPayloadEnvelope
	}

	for _, testFunc := range testFuncs {
		mock, err := beaconmock.New(t.Context())
		require.NoError(t, err)

		test := testFunc(t, &mock)
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()

			bcaster, err := bcast.New(ctx, mock, func() eth2wrap.ForkForkSchedule { return nil })
			require.NoError(t, err)

			for range test.bcastCnt {
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

func TestBroadcastOtherDuties(t *testing.T) {
	mock, err := beaconmock.New(t.Context())
	require.NoError(t, err)

	bcaster, err := bcast.New(context.Background(), mock, func() eth2wrap.ForkForkSchedule { return nil })
	require.NoError(t, err)

	err = bcaster.Broadcast(context.Background(), core.Duty{Type: core.DutyBuilderProposer}, nil)
	require.ErrorIs(t, err, core.ErrDeprecatedDutyBuilderProposer)

	err = bcaster.Broadcast(context.Background(), core.Duty{Type: core.DutyRandao}, nil)
	require.NoError(t, err)

	err = bcaster.Broadcast(context.Background(), core.Duty{Type: core.DutyPrepareAggregator}, nil)
	require.NoError(t, err)

	err = bcaster.Broadcast(context.Background(), core.Duty{Type: core.DutyPrepareSyncContribution}, nil)
	require.NoError(t, err)

	err = bcaster.Broadcast(context.Background(), core.Duty{Type: core.DutyUnknown}, nil)
	require.ErrorContains(t, err, "unsupported duty type")
}

func attData(t *testing.T, mock *beaconmock.Mock) test {
	t.Helper()

	aggData := testutil.RandomDenebCoreVersionedAttestation()
	asserted := make(chan struct{})

	var submitted int

	mock.SubmitAttestationsFunc = func(ctx context.Context, attestations *eth2api.SubmitAttestationsOpts) error {
		require.Len(t, attestations.Attestations, 1)
		require.Equal(t, aggData.VersionedAttestation, *attestations.Attestations[0])

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
		CapellaBlinded: &eth2capella.SignedBlindedBeaconBlock{
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
	aggAndProof := testutil.RandomDenebVersionedSignedAggregateAndProof()
	aggData := core.VersionedSignedAggregateAndProof{
		VersionedSignedAggregateAndProof: *aggAndProof,
	}

	mock.SubmitAggregateAttestationsFunc = func(ctx context.Context, aggregateAndProofs *eth2api.SubmitAggregateAttestationsOpts) error {
		require.Equal(t, aggAndProof, aggregateAndProofs.SignedAggregateAndProofs[0])
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

func payloadAttestationMessage(t *testing.T, mock *beaconmock.Mock) test {
	t.Helper()

	asserted := make(chan struct{})

	msg, err := core.NewVersionedPayloadAttestationMessage(testutil.RandomVersionedPayloadAttestationMessage())
	require.NoError(t, err)

	mock.SubmitPayloadAttestationMessagesFunc = func(_ context.Context, opts *eth2api.SubmitPayloadAttestationMessagesOpts) error {
		require.Len(t, opts.Messages, 1)
		require.Equal(t, msg.VersionedPayloadAttestationMessage, *opts.Messages[0])
		close(asserted)

		return nil
	}

	return test{
		name:     "Broadcast Payload Attestation Message",
		aggData:  msg,
		duty:     core.DutyPayloadAttestation,
		bcastCnt: 1,
		asserted: asserted,
	}
}

func proposerPreferences(t *testing.T, mock *beaconmock.Mock) test {
	t.Helper()

	asserted := make(chan struct{})
	prefs := core.NewSignedProposerPreferences(testutil.RandomProposerPreferences())

	mock.SubmitProposerPreferencesFunc = func(_ context.Context, opts *eth2api.SubmitProposerPreferencesOpts) error {
		preferences := opts.Preferences
		require.Len(t, preferences, 1)
		require.Equal(t, prefs.SignedProposerPreferences, *preferences[0])
		close(asserted)

		return nil
	}

	return test{
		name:     "Broadcast Proposer Preferences",
		aggData:  prefs,
		duty:     core.DutyProposerPreferences,
		bcastCnt: 1,
		asserted: asserted,
	}
}

func executionPayloadEnvelope(t *testing.T, mock *beaconmock.Mock) test {
	t.Helper()

	asserted := make(chan struct{})
	envelope := core.NewSignedExecutionPayloadEnvelope(testutil.RandomExecutionPayloadEnvelope())

	mock.SubmitExecutionPayloadEnvelopeFunc = func(_ context.Context, opts *eth2api.SubmitExecutionPayloadEnvelopeOpts) error {
		require.Equal(t, eth2spec.DataVersionGloas, opts.SignedExecutionPayloadEnvelope.Version)
		require.Equal(t, envelope.SignedExecutionPayloadEnvelope, opts.SignedExecutionPayloadEnvelope.Gloas)
		require.Equal(t, envelope.Blobs, opts.Blobs)
		require.Equal(t, envelope.KZGProofs, opts.KZGProofs)
		close(asserted)

		return nil
	}

	return test{
		name:     "Broadcast Execution Payload Envelope",
		aggData:  envelope,
		duty:     core.DutyExecutionPayloadEnvelope,
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

func TestBroadcastBuilderPreferences(t *testing.T) {
	builderConfig := &gloas.BuilderConfig{
		Builders: []*gloas.BuilderEntry{
			{URL: []byte("https://Relay-A.example.com/gloas"), MaxExecutionPayment: 7},
			{URL: []byte("https://relay-b.example.com"), MaxExecutionPayment: 7},
		},
	}

	pubkey := testutil.RandomCorePubKey(t)
	pubkeyBytes, err := pubkey.Bytes()
	require.NoError(t, err)

	newAuth := func(data string) core.SignedBuilderRequestAuth {
		return core.NewSignedBuilderRequestAuth(&gloas.SignedBuilderRequestAuth{
			Message:   &gloas.BuilderRequestAuth{Data: []byte(data), Slot: 1},
			Signature: testutil.RandomEth2Signature(),
		})
	}

	tests := []struct {
		name      string
		auth      core.SignedBuilderRequestAuth
		submitErr error
		submitted bool
		err       bool
	}{
		{
			name:      "configured builder",
			auth:      newAuth("relay-a.example.com"),
			submitted: true,
		},
		{
			name: "unconfigured builder",
			auth: newAuth("relay-z.example.com"),
		},
		{
			// The beacon node submitted the other entries, so retrying would resubmit them.
			name:      "builder rejected",
			auth:      newAuth("relay-a.example.com"),
			submitErr: &eth2api.Error{StatusCode: http.StatusBadRequest, Data: []byte(`{"code":400,"message":"some entries failed","failures":[{"index":0,"message":"unknown proposer"}]}`)},
			submitted: true,
		},
		{
			// The beacon node doesn't forward builder preferences, the auth still reaches the
			// builder with the bid request at proposal time.
			name:      "unsupported by beacon node",
			auth:      newAuth("relay-a.example.com"),
			submitErr: &eth2api.Error{StatusCode: http.StatusNotFound},
			submitted: true,
		},
		{
			name:      "beacon node error",
			auth:      newAuth("relay-a.example.com"),
			submitErr: &eth2api.Error{StatusCode: http.StatusInternalServerError},
			submitted: true,
			err:       true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mock, err := beaconmock.New(t.Context())
			require.NoError(t, err)

			var submitted []*gloas.BuilderPreferencesEntry

			mock.SubmitBuilderPreferencesFunc = func(_ context.Context, opts *eth2api.SubmitBuilderPreferencesOpts) error {
				submitted = append(submitted, opts.Preferences...)

				return test.submitErr
			}

			bcaster, err := bcast.New(t.Context(), mock, func() eth2wrap.ForkForkSchedule { return nil }, bcast.WithBuilderConfig(builderConfig))
			require.NoError(t, err)

			err = bcaster.Broadcast(t.Context(), core.NewBuilderPreferencesDuty(1), core.SignedDataSet{pubkey: test.auth})
			if test.err {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if !test.submitted {
				require.Empty(t, submitted)
				return
			}

			require.Equal(t, []*gloas.BuilderPreferencesEntry{{
				ProposerPubkey:      eth2p0.BLSPubKey(pubkeyBytes),
				URL:                 []byte("https://Relay-A.example.com/gloas"),
				Auth:                &test.auth.SignedBuilderRequestAuth,
				MaxExecutionPayment: 7,
			}}, submitted)
		})
	}
}
